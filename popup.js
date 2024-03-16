document.getElementById('scanButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  const linkInput = document.getElementById('linkInput');
  const link = linkInput.value.trim();
  
  if (!file && !link) {
    alert('Please select a file or enter a link.');
    return;
  }

  const apiKey = '90a0cae6f733f188e170ef946e5adc9daee8887abe26dfff904a50d2b7c8ec4b';
  let formData;
  let endpoint;

  if (file) {
    formData = new FormData();
    formData.append('file', file);
    endpoint = 'file/scan';
  } else {
    formData = new URLSearchParams();
    formData.append('url', link);
    endpoint = 'url/scan';
  }

  try {
    const response = await fetch(`https://www.virustotal.com/vtapi/v2/${endpoint}?apikey=${apiKey}`, {
      method: 'POST',
      body: formData
    });
    const data = await response.json();

    if (data.response_code === 1) {
      alert('The resource is safe!');
    } else {
      const message = file ? 'File' : 'Link';
      alert(`${message} is not safe!\nDetected by ${data.positives} out of ${data.total} vendors.`);
    }
  } catch (error) {
    console.error('Error:', error);
  }
});

