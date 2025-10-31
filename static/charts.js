document.addEventListener('DOMContentLoaded', function () {
  const finance = document.getElementById('financeChart');
  if (finance) {
    new Chart(finance, {
      type: 'doughnut',
      data: {
        labels: ['Approved', 'Pending', 'Rejected'],
        datasets: [{
          data: [65, 25, 10],
          backgroundColor: ['#003366', '#FFB6C1', '#142850'],
          borderWidth: 0
        }]
      }
    });
  }

  const dept = document.getElementById('deptChart');
  if (dept) {
    new Chart(dept, {
      type: 'bar',
      data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr'],
        datasets: [{
          label: 'Expenses',
          data: [3000, 4200, 2500, 5000],
          backgroundColor: '#FFB6C1'
        }]
      },
      options: { plugins: { legend: { display: false } } }
    });
  }
});
