import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import './Quiz.css';

// Define the questions and answers
const questions = [
  {
    question: "What is the largest planet in our solar system?",
    options: ["Jupiter", "Earth", "Saturn", "Mars"],
    answer: "Jupiter"
  },
  {
    question: "What is the closest star to Earth?",
    options: ["Alpha Centauri", "Sirius", "Betelgeuse", "Proxima Centauri"],
    answer: "Proxima Centauri"
  },
  {
    question: "Which planet is known as the Red Planet?",
    options: ["Venus", "Mars", "Mercury", "Neptune"],
    answer: "Mars"
  },
  {
    question: "What is the name of the galaxy that contains our solar system?",
    options: ["Andromeda", "Milky Way", "Triangulum", "Messier 87"],
    answer: "Milky Way"
  },
  {
    question: "What is the name of NASA's rover that landed on Mars in 2021?",
    options: ["Curiosity", "Perseverance", "Opportunity", "Spirit"],
    answer: "Perseverance"
  },
  {
    question: "Which planet has the most moons?",
    options: ["Earth", "Saturn", "Jupiter", "Uranus"],
    answer: "Saturn"
  },
  {
    question: "What is the name of the first human to travel into space?",
    options: ["Neil Armstrong", "Yuri Gagarin", "Buzz Aldrin", "John Glenn"],
    answer: "Yuri Gagarin"
  },
  {
    question: "What is the term for a moon that appears full and bright in the sky?",
    options: ["New Moon", "Half Moon", "Full Moon", "Crescent Moon"],
    answer: "Full Moon"
  },
  {
    question: "Which planet is known for its prominent ring system?",
    options: ["Saturn", "Jupiter", "Uranus", "Neptune"],
    answer: "Saturn"
  },
  {
    question: "What is the name of the space telescope that was launched in 1990?",
    options: ["Hubble", "Chandra", "James Webb", "Spitzer"],
    answer: "Hubble"
  }
];

const GeneralQuiz = () => {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [userAnswer, setUserAnswer] = useState('');
  const [score, setScore] = useState(0);
  const [showAnswer, setShowAnswer] = useState(false);
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });


  }, [])



  const handleAnswer = (answer) => {
    setUserAnswer(answer);
    setShowAnswer(true);
    if (answer === questions[currentQuestion].answer) {
      setScore(score + 1);
    }
  };

  const handleNextQuestion = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setShowAnswer(false);
    setUserAnswer('');
    setCurrentQuestion(currentQuestion + 1);
  };

  const handleRetakeQuiz = () => {
    setCurrentQuestion(0);
    setUserAnswer('');
    setScore(0);
    setShowAnswer(false);
  };

  return (
    <div className="quiz-video-container">
      <video src='all-quiz.mp4' autoPlay muted playsInline loop className="background-video">
        Unable to Play video
      </video>
      <div className="quiz-container">
        <div className="q-container">
          <h1>Quiz App</h1>
          <hr />
          {currentQuestion < questions.length ? (
            <>
              <h2>{questions[currentQuestion].question}</h2>
              <ul>
                {questions[currentQuestion].options.map((option, index) => (
                  <li
                    key={index}
                    onClick={() => !showAnswer && handleAnswer(option)}
                    className={
                      showAnswer
                        ? option === questions[currentQuestion].answer
                          ? 'correct'
                          : option === userAnswer
                            ? 'wrong'
                            : ''
                        : ''
                    }
                  >
                    {option}
                  </li>
                ))}
              </ul>
              {showAnswer && (
                <button className="quiz-next" onClick={handleNextQuestion}>
                  Next
                </button>
              )}
              <div className="quiz-index">{currentQuestion + 1} of {questions.length} questions</div>
            </>
          ) : (
            <div className="quiz-result">
              <h2>Your Score: {score} / {questions.length}</h2>
              <Link to={"/quiz"}><button className="quiz-next">Retake quiz</button></Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GeneralQuiz;
