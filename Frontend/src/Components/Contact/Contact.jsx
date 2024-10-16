import React from "react";
import "./Contact.css";
import Navbar from "../HomePage/Navbar/Navbar";
import { useForm } from "react-hook-form";
import { useState } from "react";
import GitHubIcon from '@mui/icons-material/GitHub';
import InstagramIcon from '@mui/icons-material/Instagram';
import LinkedInIcon from '@mui/icons-material/LinkedIn';


const Contact = () => {
    const { register, handleSubmit, formState: { errors } } = useForm();
    const [res, setRes] = useState("");

    const onSubmit = async (data) => {
        try {
            const response = await fetch('http://localhost:3001/connect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            const responseData = await response.json();
            setRes(responseData.message); // Update the state with the response message
            alert(responseData.message); // Show the alert with the response message
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred. Please try again later.');
        }
    };

    return (
        <>
            <Navbar />
            <div className="contact">
                <div className="team-section">
                    <h2>Our Team</h2>
                    <div className="team-container">
                        <div className="team-member">
                            <div className="img-container">
                                <div className="co-img1"></div>
                            </div>
                            <h3>Khush Kataruka</h3>
                            <div className="mem-social-media">
                                <ul>
                                    <li id='facebook'><a href='https://github.com/Khushkataruka/'><GitHubIcon /></a></li>
                                    <li id='instagram'><a href='https://www.instagram.com/katarukakhush/'><InstagramIcon /></a></li>
                                    <li id='linkedin'><a href='https://www.linkedin.com/in/khush-kataruka-7194822a8/;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;'><LinkedInIcon /></a></li>
                                </ul>
                            </div>
                        </div>
                        <div className="team-member">
                            <div className="img-container">
                                <div className="co-img2"></div>
                            </div>
                            <h3>Makam Lokesh</h3>
                            <div className="mem-social-media">
                                <ul>
                                    <li id='facebook'><a href='https://github.com/lokesh-makam'><GitHubIcon /></a></li>
                                    <li id='instagram'><a href='https://www.instagram.com/loke_19181/'><InstagramIcon /></a></li>
                                    <li id='linkedin'><a href='https://www.linkedin.com/in/makam-lokesh-343468321/'><LinkedInIcon /></a></li>
                                </ul>
                            </div>
                        </div>
                        <div className="team-member">
                            <div className="img-container">
                                <div className="co-img3"></div>
                            </div>
                            <h3>Mohammad Muzammil</h3>
                            <div className="mem-social-media">
                                <ul>
                                    <li id='facebook'><a href='https://github.com/u23ai105'><GitHubIcon /></a></li>
                                    <li id='instagram'><a href='https://www.instagram.com/_muzammil1008/'><InstagramIcon /></a></li>
                                    <li id='linkedin'><a href='https://www.linkedin.com/in/muzammil-mohammad-48722229b/'><LinkedInIcon /></a></li>
                                </ul>
                            </div>                        </div>
                        <div className="team-member">
                            <div className="img-container">
                                <div className="co-img4"></div>
                            </div>
                            <h3>Sahil Nagwani</h3>
                            <div className="mem-social-media">
                                <ul>
                                    <li id='facebook'><a href='https://github.com/Sahilnagwani-18'><GitHubIcon /></a></li>
                                    <li id='instagram'><a href='https://www.instagram.com/sahil.nagwani_18/'><InstagramIcon /></a></li>
                                    <li id='linkedin'><a href='https://www.linkedin.com/in/sahil-nagwani-a465ba290/'><LinkedInIcon /></a></li>
                                </ul>
                            </div>                        </div>
                    </div>
                </div>

                <section className="contact-hero">
                    <div className="contact-hero-content">
                        <h2>Get in Touch</h2>
                        <p>We'd love to hear from you. Whether you have questions, feedback, or just want to connect, reach out to us!</p>
                    </div>
                </section>

                <section className="contact-form">
                    <div className="c-container">
                        <div className="form-content">
                            <h2>Contact Us</h2>
                            <form onSubmit={handleSubmit(onSubmit)}>
                                <div className="form-group">
                                    <label htmlFor="c-name">Name</label>
                                    <input
                                        type="text"
                                        id="c-name"
                                        {...register("name", { required: true })}
                                    />
                                    {errors.name && <p className="error">Name is required</p>}
                                </div>
                                <div className="form-group">
                                    <label htmlFor="c-email">Email</label>
                                    <input
                                        type="email"
                                        id="c-email"
                                        {...register("email", { required: true })}
                                    />
                                    {errors.email && <p className="error">Email is required</p>}
                                </div>
                                <div className="form-group">
                                    <label htmlFor="c-message">Message</label>
                                    <textarea
                                        id="c-message"
                                        rows="5"
                                        {...register("message", { required: true })}
                                    ></textarea>
                                    {errors.message && <p className="error">Message is required</p>}
                                </div>
                                <button type="submit" className="submit-btn">Send Message</button>
                            </form>
                        </div>
                        <div className="contact-info">
                            <h3>Contact Information</h3>
                            <p><strong>Email:</strong> cosmicvoyage001@gmail.com</p>
                            <p><strong>Address:</strong> Ichchhanath Surat- Dumas, Road, Keval Chowk, Surat, Gujarat 395007</p>
                            <div className="map">
                                <iframe
                                    src="https://www.google.com/maps/embed?pb=!1m14!1m8!1m3!1d29764.482969729823!2d72.7778405!3d21.169887!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3be04dec8b56fdf3%3A0x423b99085d26d1f9!2sSardar%20Vallabhbhai%20National%20Institute%20of%20Technology!5e0!3m2!1sen!2sin!4v1721561248178!5m2!1sen!2sin"
                                    width="600"
                                    height="450"
                                    style={{ border: 0 }}
                                    allowFullScreen=""
                                    loading="lazy"
                                    referrerPolicy="no-referrer-when-downgrade"
                                ></iframe>
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </>
    );
};

export default Contact;
