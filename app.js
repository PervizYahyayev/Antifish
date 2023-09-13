const urlInputEl = document.getElementById("url-input");

urlInputEl.addEventListener("change", (e) => {
  //   console.log(e.target.value)
  let text = e.target.value;

  function postData(input) {
    $.ajax({
      type: "POST",
      url: "/test.py",
      data: { param: input },
      success: callbackFunc,
    });
  }

  function callbackFunc(response) {
    // do something with the response
    console.log(response);
  }

  postData("data to process");

//   $.ajax({
//     type: "POST",
//     url: "~/test.py",
//     data: { param: text },
//   }).done(function (o) {
//     console.log(o);
//   });

  //   var xhr = new XMLHttpRequest();
  //   xhr.open("POST", "test.py?text=" + e.target.value, true);
  //   xhr.onload = function (e) {
  //     console.log(xhr.response);
  //   };
  //   xhr.send();
});