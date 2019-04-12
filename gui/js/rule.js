// $("button").click(function(){
//     $.ajax({
//     	type: 'POST',
//     	url: 'http://127.0.0.1:8080/traffic/rule',
//     	data: {
//     		"data": $("#data_rule").val(),
//     		"qos": $("#qos_rule").val()
//     	}
//     	success: function(result){
//         	$("#div1").html(result);
//     }});
// });

$(document).ready(function(){
    $("#check_data_control").click(function() {
        var value = $(this).prop("checked");
        $.get( 
            "http://" + location.host + "/traffic/routing/congestion_control/" + value,
            function(result) {
                $("#is_data_control").text(result);
            }
        );
    });

    $("#rule_button").click(function(){
        var data = {};
        data['data'] = $("#data_rule").val();
        data['qos'] = $("#qos_rule").val();
        $.post(
            "http://127.0.0.1:8080/traffic/rule",
            JSON.stringify(data),
            function(result){
                $("#div1").html(result);
            }
        );
    });

    $("#qos_rule_add").click(function() {
        var data = {};
        data['src'] = $("#src").val();
        data['dst'] = $("#dst").val();
        data['proto'] = $("#proto").val();
        data['port_no'] = $("#port_no").val();
        data['rate'] = $("#rate").val();
        $.post( "http://" + location.host + "/traffic/qos_admin",
            JSON.stringify(data),
            function(result) {
                update_qos_table();
                $("#qos_result").html(result);
            }
        )
    });

    $("#update_path_table").click(function() {
        update_path_table();
    });

    function update_path_table() {
        url = "http://" + location.host + "/traffic/routing/path_table";
        $.getJSON(url, function(table) {
            var text = "<table border='1'><tr><td>path_id</td><td>src</td><td>dst</td><td>path</td><td>load(Mbps)</td>";
            $.each(table, function(path_id, rule) {
                text += "<tr>";
                text += "<td>" + path_id + "</td>";
                text += "<td>" + rule['src'] + "</td>";
                text += "<td>" + rule['dst'] + "</td>";
                text += "<td>" + rule['path'] + "</td>";
                text += "<td>" + rule['load'] + "</td>";
                text += "</tr>";
            });
            text += "</table>";
            $("#path_table").html(text);
        });
    }

    $('#update_qos_table').click(function() {
        update_qos_table();
    });

    function update_qos_table() {
        url = "http://" + location.host + "/traffic/routing/qos_rule";
        $.getJSON(url, function(table) {
            var text = "<table border='1'><tr><td>qos_id</td><td>src</td><td>dst</td><td>proto</td><td>port_no</td><td>rate(Mbps)</td><td>path</td>";
            $.each(table, function(qos_id, rule) {
                text += "<tr>";
                text += "<td>" + qos_id + "</td>";
                text += "<td>" + rule['src'] + "</td>";
                text += "<td>" + rule['dst'] + "</td>";
                text += "<td>" + rule['proto'] + "</td>";
                text += "<td>" + rule['port_no'] + "</td>";
                text += "<td>" + rule['rate'] + "</td>";
                text += "<td>" + rule['path'] + "</td>";
                text += "</tr>";
            });
            text += "</table>";
            $("#qos_table").html(text);
        });
    }

    function update_flow_loading() {
        url = "http://" + location.host + "/traffic/routing/flow_loading";
        $.getJSON(url, function(loading) {
            // var tbl  = document.createElement("table");
            // $.each(loading, function(dpid, load) {
            //     var tbl_row = tbl.insertRow();
            //     $.each(load, function(port, value) {
            //         $.each(value, function(label, flow) {
            //             var cell = tbl_row.insertCell();
            //             cell.appendChild(document.createTextNode(flow.toString()));
            //         });
            //     });
            // });
            // $("#lodading").appendChild(tbl);
            var text = "<table border='1'><tr><td>dpid</td><td>port</td><td>label</td>";
            $.each(loading, function(dpid, load) {
                text += "<tr>";
                text += "<td rowspan='" + (Object.keys(load).length+1) + "'>";
                text += dpid + "</td>";
                $.each(load, function(port, value) {
                    // text += "</tr><tr><td rowspan='" + Object.keys(value).length + "'>" + port + "</td>";
                    text += "</tr><tr><td>" + port + "</td>";
                    text += "<td>";
                    $.each(value, function(label, flow) {
                        text += classification(label) + ": " + flow.toString() + "</br>";
                    });
                    text += "</td>";
                });
                text += "</tr>";
            });
            text += "</table>";
            $("#loading").html(text);
        });
        // $.ajax({
        //     url: url,
        //     success: function(data){
        //         $("#flow_loading").html(data);
        //     }
        // });
    }

    function classification(label) {
        switch (label) {
            case "0":
                return "Data Mice Flow    "
                break;
            case "1":
                return "Data Elephant Flow"
                break;
            case "2":
                return "QoS Low Priority  "
                break;
            case "3":
                return "QoS High Priority "
                break;
        }
    }

    $("#update_link_load").click(function() {
        update_link_load();
    });
    var history_count = 0;

    function update_link_load() {
        url = "http://" + location.host + "/traffic/routing/link_loading";
        $.getJSON(url, function(loading) {
            var avg_load = 0.0
            var count = 0
            // var tbl  = document.createElement("table");
            var text = "<table border='1'><tr><td>dpid</td><td>port</td><td>link_load(Mb/s)</td>";
            $.each(loading, function(dpid, load) {
                text += "<tr>";
                text += "<td rowspan='" + (Object.keys(load).length+1) + "'>";
                text += dpid + "</td>";
                $.each(load, function(port, value) {
                    // text += "</tr><tr><td rowspan='" + Object.keys(value).length + "'>" + port + "</td>";
                    text += "</tr><tr><td>" + port + "</td>";
                    text += "<td>" + value + "</td>";
                    avg_load += parseFloat(value);
                    count += 1;
                });
                text += "</tr>";
            });
            text += "</table>";
            $("#link_table").html(text);

            avg_load = avg_load / count;
            $("#history").html(avg_load.toString() + "</br>");
            // $("html, body").animate({ scrollTop: $(document).height() }, 1000);
        });
    }
    setInterval(update_link_load, 3000);
    setInterval(update_flow_loading, 6000);
    setInterval(update_path_table, 6000);
    update_qos_table();
});