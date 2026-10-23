"""Lab 5: an in-memory infection and quarantine simulation; no files are changed."""
import random


def simulate(computers=5, rounds=5, spread_chance=0.3, quarantine_chance=0.35, seed=7):
    if not isinstance(computers, int) or isinstance(computers, bool) or not 2 <= computers <= 20:
        raise ValueError('computers must be an integer from 2 to 20')
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 1 <= rounds <= 20:
        raise ValueError('rounds must be an integer from 1 to 20')
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) and 0 <= x <= 1
               for x in (spread_chance, quarantine_chance)):
        raise ValueError('chances must be between 0 and 1')
    rng = random.Random(seed)
    states = ['healthy'] * computers
    states[0] = 'infected'
    timeline = [{'round': 0, 'states': states.copy(), 'events': ['Computer 1 starts infected']}]
    for step in range(1, rounds + 1):
        events = []
        infected = [i for i, state in enumerate(states) if state == 'infected']
        for source in infected:
            if rng.random() < quarantine_chance:
                states[source] = 'quarantined'
                events.append(f'Computer {source + 1} quarantined')
            else:
                choices = [i for i, state in enumerate(states) if state == 'healthy']
                if choices and rng.random() < spread_chance:
                    target = rng.choice(choices)
                    states[target] = 'infected'
                    events.append(f'Computer {source + 1} infected computer {target + 1}')
        timeline.append({'round': step, 'states': states.copy(), 'events': events or ['No change']})
    return {'timeline': timeline, 'final': {state: states.count(state) for state in ('healthy', 'infected', 'quarantined')}}
