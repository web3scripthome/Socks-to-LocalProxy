using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SocksLocalProxy
{
    class Program
    {
        private static readonly ILogger _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger("SocksLocalProxy");
        private static readonly List<LocalProxyServer> _proxyServers = new List<LocalProxyServer>();
        private static readonly string _socksFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SOCKS.txt");
        private static int _startPort = 55000;

        static async Task Main(string[] args)
        {

            //List<string> strings = new List<string>();
            //for (int i = 55000; i <= 55099; i++)
            //{
            //    strings.Add($"127.0.0.1:{i}");
            //}
            //File.WriteAllLines("SOCKS5.TXT",strings);
            //return;
            Console.WriteLine("SOCKS5 Local Proxy Server");
            Console.WriteLine("Reading proxy list from: " + _socksFilePath);

            if (!File.Exists(_socksFilePath))
            {
                Console.WriteLine("Error: SOCKS.txt file not found!");
                return;
            }

            var proxyLines = File.ReadAllLines(_socksFilePath);
            Console.WriteLine($"Found {proxyLines.Length} proxies in SOCKS.txt");

            foreach (var line in proxyLines)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var parts = line.Split(':');
                if (parts.Length != 4)
                {
                    Console.WriteLine($"Invalid proxy format: {line}. Expected format: IP:PORT:USER:PWD");
                    continue;
                }

                string remoteHost = parts[0];
                int remotePort = int.Parse(parts[1]);
                string username = parts[2];
                string password = parts[3];

                int localPort = _startPort++;
                var proxy = new LocalProxyServer(remoteHost, remotePort, username, password, localPort);
                _proxyServers.Add(proxy);

                try
                {
                    await proxy.StartAsync();
                    Console.WriteLine($"Started local proxy at 127.0.0.1:{localPort} -> {remoteHost}:{remotePort} (auth: {username}:{password})");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to start proxy on port {localPort}: {ex.Message}");
                }
            }

            Console.WriteLine("All proxies started. Press Ctrl+C to exit.");
            
            // Set up cancellation token to handle program termination
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (s, e) => {
                e.Cancel = true;
                cts.Cancel();
            };

            try
            {
                await Task.Delay(Timeout.Infinite, cts.Token);
            }
            catch (TaskCanceledException)
            {
                // Normal exit
            }
            finally
            {
                foreach (var proxy in _proxyServers)
                {
                    await proxy.StopAsync();
                }
                Console.WriteLine("All proxies stopped.");
            }
        }
    }

    public class LocalProxyServer
    {
        private readonly string _remoteHost;
        private readonly int _remotePort;
        private readonly string _username;
        private readonly string _password;
        private readonly int _localPort;
        private TcpListener? _listener;
        private bool _isRunning;
        private readonly ILogger _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger("LocalProxyServer");

        public LocalProxyServer(string remoteHost, int remotePort, string username, string password, int localPort)
        {
            _remoteHost = remoteHost;
            _remotePort = remotePort;
            _username = username;
            _password = password;
            _localPort = localPort;
        }

        public Task StartAsync()
        {
            _listener = new TcpListener(IPAddress.Parse("127.0.0.1"), _localPort);
            _listener.Start();
            _isRunning = true;

            // Start accepting connections in the background
            _ = Task.Run(AcceptConnectionsAsync);
            
            return Task.CompletedTask;
        }

        public Task StopAsync()
        {
            _isRunning = false;
            _listener?.Stop();
            
            return Task.CompletedTask;
        }

        private async Task AcceptConnectionsAsync()
        {
            try
            {
                while (_isRunning && _listener != null)
                {
                    var clientSocket = await _listener.AcceptSocketAsync();
                    _ = HandleClientAsync(clientSocket);
                }
            }
            catch (Exception ex) when (_isRunning)
            {
                _logger.LogError(ex, "Error accepting connections");
            }
        }

        private async Task HandleClientAsync(Socket clientSocket)
        {
            using (clientSocket)
            {
                try
                {
                    // Handle SOCKS5 initial handshake
                    byte[] buffer = new byte[1024];
                    int bytesRead = await clientSocket.ReceiveAsync(buffer, SocketFlags.None);
                    
                    // SOCKS5 initial handshake - respond with no auth required
                    if (bytesRead >= 3 && buffer[0] == 0x05)
                    {
                        // Send response: SOCKS5, No Authentication
                        byte[] response = new byte[] { 0x05, 0x00 };
                        await clientSocket.SendAsync(response, SocketFlags.None);
                        
                        // Receive connection request
                        bytesRead = await clientSocket.ReceiveAsync(buffer, SocketFlags.None);
                        
                        if (bytesRead >= 10 && buffer[0] == 0x05 && buffer[1] == 0x01) // SOCKS5, CONNECT
                        {
                            string targetHost;
                            int targetPort;
                            
                            // Parse address type
                            switch (buffer[3])
                            {
                                case 0x01: // IPv4
                                    targetHost = $"{buffer[4]}.{buffer[5]}.{buffer[6]}.{buffer[7]}";
                                    targetPort = (buffer[8] << 8) + buffer[9];
                                    break;
                                    
                                case 0x03: // Domain name
                                    int domainLength = buffer[4];
                                    targetHost = Encoding.ASCII.GetString(buffer, 5, domainLength);
                                    targetPort = (buffer[5 + domainLength] << 8) + buffer[6 + domainLength];
                                    break;
                                    
                                default:
                                    // Unsupported address type
                                    SendFailureResponse(clientSocket);
                                    return;
                            }
                            
                            // Connect to the remote SOCKS5 proxy
                            using (var remoteSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                            {
                                try
                                {
                                    await remoteSocket.ConnectAsync(_remoteHost, _remotePort);
                                    
                                    // SOCKS5 handshake with remote proxy
                                    await AuthenticateWithRemoteProxyAsync(remoteSocket);
                                    
                                    // Forward the connection request to the remote proxy
                                    await remoteSocket.SendAsync(buffer.AsMemory(0, bytesRead), SocketFlags.None);
                                    
                                    // Get response from remote proxy
                                    bytesRead = await remoteSocket.ReceiveAsync(buffer, SocketFlags.None);
                                    
                                    // Forward the response back to the client
                                    await clientSocket.SendAsync(buffer.AsMemory(0, bytesRead), SocketFlags.None);
                                    
                                    // Start bidirectional forwarding
                                    await ForwardDataAsync(clientSocket, remoteSocket);
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError(ex, $"Error connecting to remote proxy {_remoteHost}:{_remotePort}");
                                    SendFailureResponse(clientSocket);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error handling client connection");
                }
            }
        }

        private async Task AuthenticateWithRemoteProxyAsync(Socket remoteSocket)
        {
            // SOCKS5 initial handshake - request username/password auth
            byte[] authRequest = new byte[] { 0x05, 0x01, 0x02 }; // SOCKS5, 1 auth method, username/password
            await remoteSocket.SendAsync(authRequest, SocketFlags.None);
            
            // Receive auth method selection
            byte[] buffer = new byte[1024];
            int bytesRead = await remoteSocket.ReceiveAsync(buffer, SocketFlags.None);
            
            if (bytesRead < 2 || buffer[0] != 0x05 || buffer[1] != 0x02)
            {
                throw new Exception("Remote proxy doesn't support username/password authentication");
            }
            
            // Send username/password auth
            byte[] credentials = new byte[3 + _username.Length + _password.Length];
            credentials[0] = 0x01; // Auth version
            credentials[1] = (byte)_username.Length;
            Encoding.ASCII.GetBytes(_username).CopyTo(credentials, 2);
            credentials[2 + _username.Length] = (byte)_password.Length;
            Encoding.ASCII.GetBytes(_password).CopyTo(credentials, 3 + _username.Length);
            
            await remoteSocket.SendAsync(credentials, SocketFlags.None);
            
            // Receive auth response
            bytesRead = await remoteSocket.ReceiveAsync(buffer, SocketFlags.None);
            
            if (bytesRead < 2 || buffer[0] != 0x01 || buffer[1] != 0x00)
            {
                throw new Exception("Authentication with remote proxy failed");
            }
        }

        private void SendFailureResponse(Socket clientSocket)
        {
            // SOCKS5 failure response
            byte[] response = new byte[] { 0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            clientSocket.Send(response);
        }

        private async Task ForwardDataAsync(Socket clientSocket, Socket remoteSocket)
        {
            var task1 = ForwardAsync(clientSocket, remoteSocket);
            var task2 = ForwardAsync(remoteSocket, clientSocket);
            
            await Task.WhenAny(task1, task2);
        }

        private async Task ForwardAsync(Socket source, Socket destination)
        {
            byte[] buffer = new byte[8192];
            
            try
            {
                while (source.Connected && destination.Connected)
                {
                    int bytesRead = await source.ReceiveAsync(buffer, SocketFlags.None);
                    
                    if (bytesRead == 0)
                        break;
                        
                    await destination.SendAsync(buffer.AsMemory(0, bytesRead), SocketFlags.None);
                }
            }
            catch (Exception)
            {
                // Connection closed or error occurred
            }
            finally
            {
                try
                {
                    source.Shutdown(SocketShutdown.Both);
                }
                catch { }
                
                try
                {
                    destination.Shutdown(SocketShutdown.Both);
                }
                catch { }
            }
        }
    }
}
