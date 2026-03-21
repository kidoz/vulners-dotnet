using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet.Extensions;

namespace VulnersDotNet.Tests;

public abstract class IntegrationTestBase : IDisposable
{
    protected IVulnersClient Client { get; } = null!;

    private readonly ServiceProvider? _serviceProvider;

    protected IntegrationTestBase()
    {
        var apiKey = Environment.GetEnvironmentVariable("VULNERS_API_KEY");
        if (string.IsNullOrEmpty(apiKey))
        {
            Assert.Skip(
                "VULNERS_API_KEY environment variable is not set. Skipping integration tests."
            );
            return;
        }

        var services = new ServiceCollection();
        services.AddVulners(options =>
        {
            options.ApiKey = apiKey;
        });

        _serviceProvider = services.BuildServiceProvider();
        Client = _serviceProvider.GetRequiredService<IVulnersClient>();
    }

    public void Dispose()
    {
        _serviceProvider?.Dispose();
        GC.SuppressFinalize(this);
    }
}
