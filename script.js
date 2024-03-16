// import { json } from "express";

(function () {
  "use strict";
  setTimeout(createButtons, 400);

  function createButtons() {
    const links = document.querySelectorAll(
      "[data-sokoban-container] [data-header-feature] a"
    );
    for (const link of links) {
      const button = document.createElement("button");
      button.innerText = "Click me";
      button.addEventListener("click", onClick(link.href));
      link.parentElement.append(button);
    }
      
    const key = process.env.KEY;

    function onClick(url) {
      console.log(url)
      return async function (event) {
        // QUERY API
        const host = new URL(url).host
        let response = await fetch("https://virustotal-extension.herokuapp.com/?url=" + host)
        let data = await response.json()
        // ADD STATS TO DOCUMENT
        let button = event.target
        button.parentElement.append(processData(data))
      };
    }

    function processData(data) {
      let clean = 0;
      let count = 0;
      let vendorResults = data.data.attributes.last_analysis_results;

      for (let vendor in vendorResults) {
        if (vendorResults[vendor].result == "clean") {
          clean++
        }
        else if(vendorResults[vendor].result == "unrated") {
          count--
        }
        count++
      }
      let result = clean + "/" + count + " clean";
      return result
    }
  }
})();
