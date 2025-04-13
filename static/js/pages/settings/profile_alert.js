/**
 * 1개의 alert 문으로 조건이 상세함
 * @param {[string, string]} data 서버로부터 받은 데이터 입력
 * @param {Object} submitBtn submitBtn 속성
 * @param {Object} sendBtn sendBtn 속성
 * @param {Object} OEV OEV 속성
 * @param {Object} NEV NEV 속성
 */
function detail(data, submitBtn, sendBtn, OEV, NEV) {
  if (data[1] === null && data[0] === "sent") { //닉변 첫 시도
    submitBtn.disabled = false
    alert("Verification email sent successfully!")
  } else if (data[1] === null && !isNaN(data[0])) { //닉변 복수 시도
    submitBtn.disabled = false
    alert(`Verification email has been sent. You can try again in ${data} seconds.`)
  } else if (data[1] === null && data[0].startsWith("ERROR | ")) { //이메일 에러 감지
    sendBtn.disabled = false; OEV.style.display = "none"; NEV.style.display = "none"
    alert(`ERROR! report admin plz \n\n${data[0]}`)
  }
  else if (data[0] === "sent" && data[1] === "sent") { //이메일 변경 첫 시도
    submitBtn.disabled = false
    alert("Verification old & new email sent successfully!\nCheck both emails");
  } else if (!isNaN(data[0]) && !isNaN(data[1])) { //이메일 변경 복수 시도
    submitBtn.disabled = false
    alert(`Verification old & new email has been sent. You can try again in old:${data[0]}, new:${data[1]} seconds.`)
  } else if (!isNaN(data[0]) && data[1] === "sent") { //old 이미있음, new 방금보냄
    submitBtn.disabled = false
    alert(`Verification old email has been sent. You can try again in ${data[0]} seconds. \n\nVerification new email sent successfully!`)
  } else if (data[0] === "sent" && !isNaN(data[1])) { //old 방금보냄, new 이미있음 (사실상 얘는 불가능함)
    submitBtn.disabled = false
    alert(`Impossible\nVerification old email sent successfully! \n\nVerification new email has been sent. You can try again in ${data[1]} seconds.`)
  }
  else if (data[0] === "sent" && data[1].startsWith("ERROR | ")) { //old 방금보냄 + new 이메일 에러 감지
    sendBtn.disabled = false; NEV.style.display = "none"
    alert(`Verification old email sent successfully! \n\nERROR! (new) report admin plz \n\n${data[1]}`);
  } else if (!isNaN(data[0]) && data[1].startsWith("ERROR | ")) { //old 이미있음 + new 이메일 에러 감지
    sendBtn.disabled = false; NEV.style.display = "none"
    alert(`Verification old email has been sent. You can try again in ${data[0]} seconds. \n\nERROR! (new) report admin plz \n\n${data[1]}`);
  } else if (data[1] === "sent" && data[0].startsWith("ERROR | ")) { //old 이메일 에러 감지 + new 방금보냄
    sendBtn.disabled = false; OEV.style.display = "none"
    alert(`Verification new email sent successfully! \n\nERROR! (old) report admin plz \n\n${data[0]}`);
  } else if (!isNaN(data[1]) && data[0].startsWith("ERROR | ")) { //old 이메일 에러 감지 + new 이미있음
    sendBtn.disabled = false; OEV.style.display = "none"
    alert(`Verification new email has been sent. You can try again in ${data[1]} seconds. \n\nERROR! (old) report admin plz \n\n${data[0]}`);
  } else if (data[0].startsWith("ERROR | ") && data[1].startsWith("ERROR | ")) { //둘다 이메일 에러 감지
    sendBtn.disabled = false; OEV.style.display = "none"; NEV.style.display = "none"
    alert(`ERROR! (both) report admin plz \n\n${data[0]}\n\n${data[1]}`);
  }
}

/**
 * 2개의 alert 문으로 조건이 간편함
 * @param {[string, string]} data 서버로부터 받은 데이터 입력
 * @param {Object} submitBtn submitBtn 속성
 * @param {Object} sendBtn sendBtn 속성
 * @param {Object} OEV OEV 속성
 * @param {Object} NEV NEV 속성
 */
function simple(data, submitBtn, sendBtn, OEV, NEV) {
  if (data[0] === "sent") {
    submitBtn.disabled = false
    alert("Verification old email sent successfully!")
  } else if (!isNaN(data[0])) {
    submitBtn.disabled = false
    alert(`Verification old email has been sent. You can try again in ${data[0]} seconds.`)
  } else if (data[0].startsWith("ERROR | ")) {
    sendBtn.disabled = false; OEV.style.display = "none"
    alert(`ERROR! (old) report admin plz \n${data[0]}`)
  }
  if (!data[1]);
  else if (data[1] === "sent") {
    submitBtn.disabled = false
    alert("Verification new email sent successfully!")
  } else if (!isNaN(data[1])) {
    submitBtn.disabled = false
    alert(`Verification new email has been sent. You can try again in ${data[1]} seconds.`)
  } else if (data[1].startsWith("ERROR | ")) {
    sendBtn.disabled = false; NEV.style.display = "none"
    alert(`ERROR! (new) report admin plz \n${data[1]}`)
  }
}