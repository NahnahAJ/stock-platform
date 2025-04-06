<a name="readme-top"></a>

<div align="center">
  <h3 align="center">📦 Stock & Point of Sale System</h3>
  <p align="center">Inventory, sales, and supplier management system for retail businesses</p>
</div>

# 📗 Table of Contents

- [📖 About the Project](#about-project)
  - [🛠 Built With](#built-with)
    - [Tech Stack](#tech-stack)
    - [Key Features](#key-features)
  - [🚀 Live Demo](#live-demo)
- [💻 Getting Started](#getting-started)
  - [Setup](#setup)
  - [Prerequisites](#prerequisites)
  - [Install](#install)
  - [Usage](#usage)
  - [Run tests](#run-tests)
  - [Deployment](#triangular_flag_on_post-deployment)
- [👥 Authors](#authors)
- [🔭 Future Features](#future-features)
- [🤝 Contributing](#contributing)
- [⭐️ Show your support](#support)
- [🙏 Acknowledgements](#acknowledgements)
- [❓ FAQ (OPTIONAL)](#faq)
- [📝 License](#license)

# 📖 Stock & Point of Sale System <a name="about-project"></a>

**Stock & Point of Sale System** is a complete inventory and sales management tool tailored for retail shops. It helps manage products, suppliers, customers, debts, and generate reports for smarter business decisions.

## 🛠 Built With <a name="built-with"></a>

### Tech Stack <a name="tech-stack"></a>

<details>
  <summary>Client</summary>
  <ul>
    <li>Vanilla JavaScript</li>
    <li>HTML & CSS (ERB Templates)</li>
  </ul>
</details>

<details>
  <summary>Server</summary>
  <ul>
    <li>Ruby on Rails</li>
  </ul>
</details>

<details>
<summary>Database</summary>
  <ul>
    <li>PostgreSQL</li>
  </ul>
</details>

### Key Features <a name="key-features"></a>

- ✅ Stock tracking (items, categories, quantities, manufacturer)
- 🛒 Purchase and Sales tracking
- 🧾 Supplier and Order management
- 🚨 Low-stock alerts
- 📊 Reports and analytics
- 🔎 Searchable inventory
- 💳 Customer debt tracking

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 🚀 Live Demo <a name="live-demo"></a>

- _Coming soon_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 💻 Getting Started <a name="getting-started"></a>

To get a local copy up and running, follow these steps.

### Prerequisites

Install the following:

```sh
  ruby >= 3.0
  rails >= 7.0
  postgresql
  bundler
```

### Setup

Clone this repository to your desired folder:

```sh
  cd your-folder-name
  git clone https://github.com/yourusername/stock-pos-system.git
```

### Install

Install dependencies:

```sh
  bundle install
  yarn install # If using webpacker
```

### Usage

To run the project, execute:

```sh
  rails db:create
  rails db:migrate
  rails s
```

Visit [http://localhost:3000](http://localhost:3000)

### Run tests

To run tests, run:

```sh
  bin/rails test
```

### Deployment

You can deploy this project using:

- Heroku
- Render
- DigitalOcean (with Capistrano or Docker)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 👥 Authors <a name="authors"></a>

👤 **Felicia G. Awuah**

- GitHub: [Felicia G. Awuah](https://github.com/NahnahAJ)
- Twitter: [@yourtwitterhandle](https://twitter.com/yourtwitterhandle)
- LinkedIn: [Felicia G. Awuah](https://www.linkedin.com/in/felicia-awuah-gyedua/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 🔭 Future Features <a name="future-features"></a>

- [ ] Multi-store support
- [ ] Barcode scanner integration
- [ ] Export to CSV or Excel
- [ ] Mobile-friendly POS screen

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 🤝 Contributing <a name="contributing"></a>

Contributions, issues, and feature requests are welcome!

Feel free to check the [issues page](../../issues/).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## ⭐️ Show your support <a name="support"></a>

If you like this project, give it a ⭐️ and share it with someone who might find it helpful!

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 🙏 Acknowledgements <a name="acknowledgements"></a>

- Special thanks to my family and business partners who inspired this idea.
- Ruby on Rails community for fantastic documentation and gems.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## ❓ FAQ (OPTIONAL) <a name="faq"></a>

- **Can I use this for my own retail shop?**  
  Absolutely! It’s open source—just fork and customize it.

- **Does it work offline?**  
  Not yet, but future updates may support offline-first capabilities with service workers.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## 📝 License <a name="license"></a>

This project is [MIT](./LICENSE) licensed.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
