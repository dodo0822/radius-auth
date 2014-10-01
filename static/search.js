$(function(){
	
	$('#keys li a').click(function(){
		var $a = $(this);
		$('#current-key').html($a.html());
		$('#key-field').val($a.data('key'));
	});
	
	$('#keys li:first-child a').click();
	
});