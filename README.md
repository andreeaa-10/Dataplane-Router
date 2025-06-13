In cadrul primei teme la PCOM am realizat implementarea dataplane-ului unui router, finalizând toate task-urile în decurs de aproximativ 20 de ore.

## Functionalitati implementate 

### Procesul de dirijare
- am inceput prin a verifica faptul ca primesc un pachet IP
- am comparat checksum-ul primit cu cel recalculat pentru a verifica integritatea pachetului, in caz contrar i-am dat drop
- am verificat valoarea ttl-ului, iar daca era mai mic sau egal cu 1 ii dadeam drop
- am scazut ttl-ul si am recalculat checksum-ul
- am cautat next_hop-ul in tabela de rutare, in cazul in care nu-l gaseam dadeam drop pachetului
- avand next_hop dat, am cautat in tabela statica de arp intrarea mac pentru el, in cazul in care nu o gaseam dand drop
- am adaugat intrarea MAC in header-ul de ETHERNET si am trimis pachetul mai departe

## Longest Prefix Match
- pentru a implementa un LPM eficient am folosit un trie binar, pentru care cautarea este mai eficienta decat cautarea liniara 
- functiile pe care le-am implementat pe trie sunt: trie_create, trie_insert, get_best_route si free_tree
- fiecare bit din adresa IP este un nivel în trie, am inserat rutele în functia trie_insert, folosind masca pentru a determina adancimea fiecarei rute
- funcția get_best_route parcurge trie-ul, bit cu bit, alegand ramura potrivita (0 sau 1) in functie de adresa IP de destinatie
- in functia main am initializat trie-ul, am parsat tabela de rutare in trie, iar la primirea unui pachet de IP, dupa verificarile necesare, am cautat next_hop-ul, folosind get_best_route

## Protocolul ARP
- am implementat protocolul ARP, folosind o lista simpla drept cache-ul ARP-ului si o coada pentru gestionarea pachetelor ce asteapta reply
- am definit funcțiile add_arp_entry, find_arp_entry și free_arp_cache, care mă ajută să gestionez conținutul cache-ului ARP
- am modificat logica din main pentru a gestiona atat primirea pachetelor de tip ARP, cat si crearea unui ARP request, astfel:
    - in cazul in care primesc un pachet IP corect, iar la cautarea in cache-ul ARP nu gasesc un MAC asociat adresei mele next_hop, adaug pachetul asociat next_hop-ului in coada de pachete si creez un pachet ARP de tip request pe care il voi trimite mai departe
    - pentru trimiterea unui request am completat pachetul Ethernet și ARP corespunzător, folosind broadcast pentru MAC-ul destinației
    - in cazul in care primesc un pachet ARP, verific codul operatiei(request sau reply) si tratez fiecare caz
        - dacă primesc un pachet ARP de tip request, modific pachetul astfel încât să-l trimit ca reply, păstrând restul informațiilor necesare și inversând adresele IP și MAC
        - dacă primesc un pachet ARP de tip reply, adaug adresa MAC în cache-ul ARP, apoi parcurg coada de pachete și le trimit pe cele pentru care găsesc o adresă MAC validă în cache

## Protocolul ICMP 
- am implementat protocolul ICMP pentru a genera mesaje de eroare de tip ICMP Time Exceeded și ICMP Host Unreachable, precum și pentru a răspunde la mesaje de tip ICMP Echo Request
- in functia main am adaugat la procesul de dirijare al unui pachet IP logica de trimitere a mesajelor de eroare si a raspunsurilor pentru echo request
- în cazul în care TTL-ul ajunge la o valoare mai mică decât 1, trimit un mesaj de tip ICMP Time Exceeded, construind un pachet ICMP de la zero peste un pachet IP
- în cazul în care funcția get_best_route nu returnează vreun next_hop, trimit un mesaj ICMP Host Unreachable, folosind aceeasi functie ca in cazul de mai sus, cu exceptia faptului ca voi schimba campurile type si code
- în cazul în care adresa de destinație este chiar routerul (adică am primit un ICMP Echo Request), trimit mai departe un mesaj de tip ICMP Echo Reply
- în toate aceste cazuri am recalculat corect checksum-urile IP și ICMP și am completat câmpurile de MAC pentru a trimite pachetul înapoi pe interfața corespunzătoare

## Probleme intampinate
- o prima problema intampinata a fost gestionarea conversiilor intre formatul little endian si big endian, in cadrul procesului de dirijare, unde am stat ceva timp sa inteleg cum sa interpertez corect unele adrese 
- protocolul ICMP a fost o zona cu formulari putin ambigue in cerinta, unde am ramas blocata pana am inteles corect cum trebuie gestionate mesajele de eroare vs cele de reply
- protocolul ARP a reprezentat o parte complexa a temei, unde era nevoie de multa atentie, intrucat un mic detaliu modificat putea sa duca la o executie gresita a codului, mai ales la partea de constructie a unui ARP Request, cat si gestionarea cozii de pachete

## Referinte 
- https://vinesmsuic.github.io/notes-networkingIP-L3/index.html
- en.wikipedia.org/wiki/Address_Resolution_Protocol
- https://leetcode.com/problems/implement-trie-prefix-tree/description/
- https://networkdirection.net/articles/network-theory/icmpforipv4/