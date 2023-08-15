function toggleAccordion(event) {
    var section = event.currentTarget;
    var content = section.querySelector(".accordion-content");
    content.classList.toggle("active");
}

document.addEventListener("DOMContentLoaded", function () {
    var accordionHeaders = document.querySelectorAll(".accordion-header");
    accordionHeaders.forEach(function (header) {
        header.addEventListener("click", toggleAccordion);
    });
});