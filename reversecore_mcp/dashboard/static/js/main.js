/**
 * Reversecore MCP Dashboard JavaScript
 */

document.addEventListener('DOMContentLoaded', function () {
    console.log('Reversecore MCP Dashboard loaded');

    // Auto-refresh stats every 30 seconds on overview page
    if (window.location.pathname === '/dashboard/') {
        setInterval(function () {
            // Could implement AJAX refresh here
        }, 30000);
    }

    // Handle function list clicks
    const functionItems = document.querySelectorAll('.function-list li');
    functionItems.forEach(item => {
        item.addEventListener('click', function () {
            // Could implement function-specific disassembly here
            const funcName = this.querySelector('.func-name').textContent;
            console.log('Selected function:', funcName);
        });
    });
});
