const dropArea = document.querySelector(".drop_box"),
  button = dropArea.querySelector("button"),
  title = dropArea.querySelector("h4"),
  dragText = dropArea.querySelector("header"),
  input = dropArea.querySelector("input");
let file;
var filename;

button.onclick = () => {
  input.click();
};

input.addEventListener("change", function (e) {
  var fileName = e.target.files[0].name;
  //   let filedata = `
  //     <form method="POST" enctype="multipart/form-data">
  //     <div class="form">
  //     <h4>${fileName}</h4>
  //     <input type="email" placeholder="Enter email upload file">
  //     <button class="btn">Upload</button>
  //     </div>
  //     </form>`;
  title.innerText = fileName;
});
