import 'dotenv/config';
import { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } from '@google/generative-ai';
import fetch, { Headers } from 'node-fetch';
import readline from 'readline';
import bcrypt from 'bcrypt';
import fs from 'fs';
import say from 'say';

globalThis.fetch = fetch;
globalThis.Headers = Headers;

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const usersFile = './users.json';
const logFile = './conversationLogs.json';
const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
const MODEL_NAME = "gemini-pro";
const API_KEY = process.env.API_KEY;

const UserManager = {
  getUsers() {
    if (!fs.existsSync(usersFile)) {
      fs.writeFileSync(usersFile, JSON.stringify({}));
    }
    return JSON.parse(fs.readFileSync(usersFile, 'utf8'));
  },

  saveUsers(users) {
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
  },

  async registerUser(username, password) {
    const users = this.getUsers();
    if (users[username]) {
      throw new Error(`User ${username} already exists`);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { password: hashedPassword };
    this.saveUsers(users);
    console.log(`User ${username} registered successfully.`);
  },

  async authenticateUser(username, password) {
    const users = this.getUsers();
    if (!users[username]) {
      throw new Error(`User ${username} does not exist`);
    }
    const valid = await bcrypt.compare(password, users[username].password);
    if (!valid) {
      throw new Error('Invalid password');
    }
    console.log(`User ${username} authenticated successfully.`);
    return true;
  }
};

const Logger = {
  logConversation(user, message, response) {
    let logs = [];
    if (fs.existsSync(logFile)) {
      logs = JSON.parse(fs.readFileSync(logFile, 'utf8'));
    }
    logs.push({ user, message, response, timestamp: new Date().toISOString() });
    fs.writeFileSync(logFile, JSON.stringify(logs, null, 2));
  },

  viewAllLogs() {
    if (!fs.existsSync(logFile)) {
      console.log("No logs available.");
      return;
    }
    const logs = JSON.parse(fs.readFileSync(logFile, 'utf8'));
    console.log("All Conversation Logs:");
    logs.forEach(log => {
      console.log(`[${log.timestamp}] User: ${log.user}, Message: ${log.message}, Response: ${log.response}`);
    });
  }
};

async function runChat(userInput) {
  const genAI = new GoogleGenerativeAI(API_KEY);
  const model = await genAI.getGenerativeModel({ model: MODEL_NAME });

  const generationConfig = {
    temperature: 0.9,
    topK: 1,
    topP: 1,
    maxOutputTokens: 1000,
  };

  const safetySettings = [
    {
      category: HarmCategory.HARM_CATEGORY_HARASSMENT,
      threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
  ];

  const chat = model.startChat({
    generationConfig,
    safetySettings,
    history: [
      {
        role: "user",
        parts: [{ text: "Hello, I have a question for you." }],
      },
      {
        role: "model",
        parts: [{ text: "Hi! How can I assist you today?" }],
      },
    ],
  });

  try {
    const result = await chat.sendMessage(userInput);
    const response = result.response;
    return response.text();
  } catch (error) {
    console.error('Error during chat:', error);
    throw error;
  }
}

const askQuestion = (query) => {
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      resolve(answer);
    });
  });
};

async function startAdminMode() {
  const password = await askQuestion("Enter admin password: ");
  if (password === adminPassword) {
    Logger.viewAllLogs();
  } else {
    console.log("Invalid password.");
  }
}

async function run() {
  try {
    console.log("Welcome to the Terminal-based Chatbot!");
    const action = await askQuestion("Do you want to (login/register/admin)? ");

    if (action === 'admin') {
      await startAdminMode();
      rl.close();
      return;
    }

    const username = await askQuestion("Enter username: ");
    const password = await askQuestion("Enter password: ");

    if (action === 'register') {
      await UserManager.registerUser(username, password);
      await runChatBotInteraction(username);
    } else if (action === 'login') {
      await UserManager.authenticateUser(username, password);
      await runChatBotInteraction(username);
    } else {
      console.log("Invalid action.");
      rl.close();
    }

  } catch (error) {
    console.error("Error:", error.message);
    rl.close();
  }
}

async function runChatBotInteraction(user) {
  console.log("Type 'exit' or 'quit' to end the chat.");
  
  while (true) {
    const msg = await askQuestion("Please enter your question: ");
    if (msg.toLowerCase() === 'exit' || msg.toLowerCase() === 'quit') {
      console.log("Exiting the chat. Goodbye!");
      rl.close();
      return;
    }

    try {
      const response = await runChat(msg);
      console.log(`Bot: ${response}`);
      
      say.stop();
      say.speak(response);
      
      Logger.logConversation(user, msg, response);
    } catch (error) {
      console.error("Error generating response:", error.message);
    }
  }
}

run();
