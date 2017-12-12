A parser for <b>wpscan tool</b>(not wpscan-v3) with python.
<br />the result is a json with 3 section:<br />
1-Body<br />
2-Header<br />
3-Footer<br /><br />
<ul>
    <li>Body contain vulnerability such as XSS, SQLinjection, ... each item has 5 parts:
        <br />- "porblem": witch version(s) have this problem.
        <br />- "vulnerability": what is the problem.
        <br />- "severity": 'i' for information type or '!' for other kinds(more dangerous).
        <br />- "reference": it's a array of links for more information about this problem.
        <br />- "fixed": witch version have fixed this problem(can be null).
    </li>
    <br />
    <li>Header is parsed part of head wpscan tool file such as started time, url, config, ... each item has 2 parts:
        <br />- "severity"
        <br />- "detail": some info about the item.
    </li>
    <br />
    <li>Footer have some information about finished time, elapsed time, used theme, ... each item has 2 parts:
        <br />- "severity"
        <br />- "detail": some info about the item.
    </li>
</ul>
<b>Notic:<b>the input file(wpscan tool result) must be with the colorize string. for clear text (without colorize) it's another topic branch or someting!!
