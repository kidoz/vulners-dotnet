namespace VulnersDotNet.Tests;

public class StixServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task MakeBundleByIdAsync_ReturnsBundle()
    {
        var result = await Client.Stix.MakeBundleByIdAsync(
            "CVE-2021-44228",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEqual(default, result);
    }
}
