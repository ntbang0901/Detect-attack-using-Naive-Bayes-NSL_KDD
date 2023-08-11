Chart.defaults.global.defaultFontFamily =
    '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif'

Chart.defaults.global.defaultFontColor = "#292b2c"

// Configure Pusher instance
const pusher = new Pusher("4ffaf8d3702be38b0e7b", {
    cluster: "us3",
    encrypted: true,
})

// Subscribe to poll trigger
var orderChannel = pusher.subscribe("order")

// Listen to 'order placed' event
// var order = document.getElementById("order-count")
// orderChannel.bind("place", function (data) {
//     myLineChart.data.datasets.forEach((dataset) => {
//         dataset.data.fill(parseInt(data.units), -1)
//     })
//     myLineChart.update()
//     order.innerText = parseInt(order.innerText) + 1
// })

var normalChannel = pusher.subscribe("normal")
var attackChannel = pusher.subscribe("attack")

// Listen to 'order placed' event
var order = document.getElementById("normal-count")
var attack = document.getElementById("attack-count")
normalChannel.bind("push", function (data) {
    order.innerText = parseInt(order.innerText) + 1
})
attackChannel.bind("push", function (data) {
    attack.innerText = parseInt(attack.innerText) + 1
})
