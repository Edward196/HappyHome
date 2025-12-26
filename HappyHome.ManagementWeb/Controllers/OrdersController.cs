using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
namespace HappyHome.ManagementWeb.Controllers;

[Authorize]
public class OrdersController : Controller
{
    private readonly IHappyHomeApiClient _api;
    public OrdersController(IHappyHomeApiClient api) => _api = api;

    public async Task<IActionResult> Index()
    {
        var orders = await _api.GetOrdersAsync();
        return View(orders);
    }
}