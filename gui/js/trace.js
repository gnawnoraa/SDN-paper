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
    $("#update_path_table").click(function() {
        update_path_table();
    });
    var history_count = 0;

    function update_path_table() {
        url = "http://" + location.host + "/traffic/routing/path_table";
        $.getJSON(url, function(table) {
            var text = "<table border='1'><tr><td>path_id</td><td>src</td><td>dst</td><td>path</td><td>load(Mbps)</td>";
            var avg_load = 0.0;
            var count = 0;
            $.each(table, function(path_id, rule) {
                text += "<tr>";
                text += "<td>" + path_id + "</td>";
                text += "<td>" + rule['src'] + "</td>";
                text += "<td>" + rule['dst'] + "</td>";
                text += "<td>" + rule['path'] + "</td>";
                text += "<td>" + rule['load'] + "</td>";
                text += "</tr>";
                avg_load += parseFloat(rule['load']);
                count += 1;
            });
            text += "</table>";
            $("#path_table").html(text);
            avg_load = avg_load / count;
            $("#history").append(avg_load.toString() + "</br>");
            history_count += 1;
            $("#count").html("History Count: " + history_count.toString());
        });
    }

    setInterval(update_path_table, 3000);
});