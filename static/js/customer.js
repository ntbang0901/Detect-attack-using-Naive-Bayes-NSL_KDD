$(document).ready(function () {
    var detectChannel = pusher.subscribe("detect")

    var dataTableDetect = $("#dataTableDetect").DataTable({
        order: [[7, "desc"]],
    })
    detectChannel.bind("push", function (data) {
        dataTableDetect.row
            .add([
                data.protocol_type,
                data.service,
                data.flag,
                data.src_ip,
                data.src_port,
                data.dst_ip,
                data.dst_port,
                data.ltime,
                data.detect,
            ])
            .draw(false)
    })
})
