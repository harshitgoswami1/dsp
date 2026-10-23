"""Lab 11b: k-anonymity with l-diversity, t-closeness, and risk measurements."""
from collections import Counter, defaultdict
from secrets import SystemRandom

RANDOM = SystemRandom()


def groups(rows, qis):
    result = defaultdict(list)
    for row in rows:
        result[tuple(row.get(q) for q in qis)].append(row)
    return result


def risk(rows, qis):
    if not rows:
        return {'minimum_class_size': 0, 'maximum_reidentification_risk': 0, 'unique_fraction': 0}
    sizes = [len(group) for group in groups(rows, qis).values()]
    return {'minimum_class_size': min(sizes), 'maximum_reidentification_risk': 1 / min(sizes),
            'unique_fraction': sum(size for size in sizes if size == 1) / len(rows)}


def anonymize(rows, qis, sensitive, k=2, l=1, t=1.0, epsilon=1.0):
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError('rows must be a nonempty list of objects')
    if not isinstance(qis, list) or not qis or not all(isinstance(q, str) for q in qis):
        raise ValueError('quasi_identifiers must be a nonempty list of column names')
    if len(set(qis)) != len(qis) or sensitive in qis or not all(all(q in row for q in qis + [sensitive]) for row in rows):
        raise ValueError('Every row must have the quasi-identifiers and sensitive column')
    if not isinstance(k, int) or isinstance(k, bool) or k < 2 or k > len(rows):
        raise ValueError('k must be an integer from 2 to the row count')
    if not isinstance(l, int) or isinstance(l, bool) or l < 1 or not isinstance(t, (int, float)) or not 0 <= t <= 1:
        raise ValueError('l must be positive and t must be between 0 and 1')
    if not isinstance(epsilon, (int, float)) or isinstance(epsilon, bool) or epsilon <= 0:
        raise ValueError('epsilon must be positive')
    before = risk(rows, qis)
    # Release only the chosen quasi-identifiers and sensitive column.
    safe = [{key: row[key] for key in qis + [sensitive]} for row in rows]
    # Generalize all quasi-identifiers together until every class has at least k rows.
    # Suppression is the final fallback and guarantees the requested k.
    for level in range(4):
        candidate = []
        for row in safe:
            item = row.copy()
            for q in qis:
                value = str(item[q])
                if level == 0:
                    continue
                if q.lower() == 'age' and value.isdigit():
                    width = (10, 20, 100)[level - 1]
                    start = int(value) // width * width
                    item[q] = f'{start}-{start + width - 1}'
                elif q.lower() in ('zip', 'zipcode', 'postal_code'):
                    item[q] = value[:max(0, len(value) - level)] + '*' * min(level, len(value))
                else:
                    item[q] = '*' if level >= 2 else value
            candidate.append(item)
        if min(len(group) for group in groups(candidate, qis).values()) >= k:
            break
    else:
        candidate = [{**row, **{q: '*' for q in qis}} for row in safe]
    classes = groups(candidate, qis)
    global_dist = Counter(str(row[sensitive]) for row in candidate)
    total = len(candidate)
    diversity = all(len({str(row[sensitive]) for row in group}) >= l for group in classes.values())
    closeness = all(0.5 * sum(abs(Counter(str(row[sensitive]) for row in group)[value] / len(group) - count / total)
                                for value, count in global_dist.items()) <= t for group in classes.values())
    # The count query has sensitivity 1; this is a separate aggregate demo.
    noisy_count = total + RANDOM.expovariate(epsilon) - RANDOM.expovariate(epsilon)
    return {'rows': candidate, 'risk_before': before, 'risk_after': risk(candidate, qis),
            'k_anonymous': True, 'l_diverse': diversity, 't_close': closeness,
            'dp_noisy_count': noisy_count}
