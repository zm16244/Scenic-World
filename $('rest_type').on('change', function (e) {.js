$('city_link').on('change', function (e) {
    var optionSelected = $("option:selected", this);
    var text = optionSelected.text;
    if(text == "Select City"){
    	console.log("helo");
    	$('goButton').hide();
    }else{
    	console.log("helssso");
    	$('goButton').show();
    }
});

