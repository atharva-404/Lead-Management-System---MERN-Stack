
# 📌 Lead Management System – MERN Stack

A **minimal MERN-stack application** built for an internship machine test.  
It allows **Admin login, Agent management, CSV/XLSX lead upload, and automatic distribution of leads among agents.**


---



## 🚀 Features
- 🔑 Admin Login (JWT authentication)  
- 👨‍💼 Agent Creation & Management  
- 📂 Upload CSV files  
- ⚖️ Distribute leads equally among first 5 agents  
- 💾 Store leads in MongoDB  
- 📊 Frontend dashboard to view agents and assigned leads  


---



## 📂 Project Structure
```

.
├── backend/   # Express + MongoDB + JWT authentication
├── frontend/  # React.js dashboard

````
----


## ⚙️ Tech Stack
- **Frontend:** React.js, Axios  
- **Backend:** Node.js, Express.js, JWT  
- **Database:** MongoDB (Mongoose ODM)  

---

## 🛠️ Setup Instructions

### 1. Clone Repository
```bash
git clone https://github.com/atharva-404/Lead-Management-System---MERN-Stack.git
````

### 2. Backend Setup

```bash
cd backend
npm install
```

Create a `.env` file inside `backend/`:

```
PORT=5000
MONGO_URI=mongodb://localhost:27017/lead_management
JWT_SECRET=your_jwt_secret
```


Run the backend:

```bash
npm start

```

👉 Runs on: **[http://localhost:5000](http://localhost:5000)**

---

### 3. Frontend Setup

```bash
cd frontend
npm install
npm start
```

👉 Runs on: **[http://localhost:3000](http://localhost:3000)**

---

## 📌 API Endpoints


### 🔑 Admin Login

```http
POST /api/auth/login
```

**Request Body:**

```json
{
  "email": "admin@test.com",
  "password": "123456"
}
```

### 👨‍💼 Add Agent

```http
POST /api/agents
Authorization: Bearer <admin_jwt_token>
```

**Request Body:**

```json
{
  "name": "Agent 1",
  "email": "agent1@test.com",
  "mobile": "+919876543210",
  "password": "1234567"
} 
```

### 📂 Upload Leads

```http
POST /api/leads/upload
Authorization: Bearer <admin_jwt_token>
Content-Type: multipart/form-data
```

---

## 🖥️ Demo Flow

1. Admin logs in and gets a JWT token
2. Admin adds up to 5 agents
3. Upload a CSV file with leads
4. Leads are distributed equally among agents and saved in MongoDB
5. Dashboard displays agents and their assigned leads

---

## 👨‍💻 Author


 **Atharva Sonar** – Internship Project Submission


