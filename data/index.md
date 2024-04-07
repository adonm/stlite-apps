---
sql:
    attack: ./enterprise-attack.parquet
---

# MITRE attack framework viewer

```sql
SELECT type, COUNT(*) FROM attack
GROUP BY type
ORDER BY count_star() DESC;
```
## Mitre Tactics

Future testing should look at how easy to construct graph fragments (e.g. technique list with tactic metadata available etc)

Would it be easier to create a few 'cleaned' tables using pandas, or using the duckdb sql in observable? Both seem v.powerful.

```sql
select name from attack
where type = 'x-mitre-tactic';
```

## Mitre techniques

```sql id=techniques
select {"id": external_id, "name": name, "url": url} as technique from attack
where type = 'attack-pattern';
```

Once loading techniques test a basic html format output

```js
Inputs.table(techniques, { format: {
    technique: (x) => htl.html`<a href="${x.url}">${x.id} - ${x.name}</a>`
}})
```
