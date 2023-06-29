from collections import Counter

# Citim continutul fisierului blocked_sites.txt
with open('blocked_sites.txt', 'r') as file:
    content = file.read()
sites = content.split('\n')

# Variabile pentru contorizare
google_count = 0
facebook_count = 0
other_companies = []

# Iteram prin fiecare nume de site
for site in sites:
    if 'google' in site:
        google_count += 1
    elif 'facebook' in site:
        facebook_count += 1
    else:
        other_companies.append(site)

# Determinam frecventa site-urilor din "other_companies"
companies_frequency = Counter(other_companies)

# Gasim primele 10 site-uri cele mai frecvente din lista
most_frequent_companies = companies_frequency.most_common(10)

# Afiseaza numaratoarea si companiile cele mai frecvente
print(f"Numarul de site-uri blocate care contin:")
print(f"'google': {google_count}")
print(f"'facebook': {facebook_count}\n")
print("Cele mai frecvente companii blocate:")
for company, count in most_frequent_companies:
    print(f"{company}: {count} aparitii")
