import io, os, re, sys
sys.stdout.reconfigure(encoding='utf-8')

R = r'C:\Users\Angus\Desktop\pi\seep\project\Seep-Tool-Docs'
ADV = os.path.join(R, 'docs', '04-安全公告')

# 模式文件夹 -> (编号, 名称, 靶场点位文档相对路径)
PAT = {
    '01-单点布尔裁决':          ('01', '单点布尔裁决',          '../05-教学靶场/patch-points/01-单点布尔裁决.md'),
    '02-硬编码密钥材料':        ('02', '硬编码密钥材料',        '../05-教学靶场/patch-points/02-硬编码密钥材料.md'),
    '03-动态库加载顺序缺陷':    ('03', '动态库加载顺序缺陷',    '../05-教学靶场/patch-points/03-动态库加载顺序缺陷.md'),
    '04-可写全局状态变量':      ('04', '可写全局状态变量',      '../05-教学靶场/patch-points/04-可写全局状态变量.md'),
    '05-明文进程间通信':        ('05', '明文进程间通信',        '../05-教学靶场/patch-points/05-明文进程间通信.md'),
    '06-自研弱校验算法':        ('06', '自研弱校验算法',        None),
    '07-空值短路校验-Fail-Open': ('07', '空值短路校验 (Fail-Open)', '../05-教学靶场/patch-points/07-空值短路校验-Fail-Open.md'),
}

# 建立：产品文件 -> 它所属的全部模式
prod_pats = {}
for pdir in os.listdir(ADV):
    full = os.path.join(ADV, pdir)
    if not os.path.isdir(full) or pdir not in PAT:
        continue
    for fn in os.listdir(full):
        if fn.endswith('.md') and fn != 'README.md':
            prod_pats.setdefault(fn, []).append(pdir)

def prio(p):
    return PAT[p][0]

count = 0
for fn, pats in sorted(prod_pats.items()):
    pats = sorted(set(pats), key=prio)
    # 定位该产品的「主模式文件夹」（编号最小的那个）
    primary = pats[0]
    fp = os.path.join(ADV, primary, fn)
    if not os.path.exists(fp):
        print('[!] 主文件不存在: %s' % fp)
        continue
    t = io.open(fp, encoding='utf-8').read()
    if '## 🎯 动手实践' in t:
        continue

    rows = []
    for p in pats:
        num, name, lab = PAT[p]
        if lab:
            rows.append('| 模式 %s | %s | [%s](../../05-教学靶场/patch-points/%s.md) |'
                        % (num, name, '进入靶场 →', os.path.basename(lab)))
        else:
            rows.append('| 模式 %s | %s | （无独立靶场，见[模式矩阵](../../01-理论基础/02-客户端脆弱性模式矩阵.md)） |'
                        % (num, name))

    section = (
        '\n---\n\n'
        '## 🎯 动手实践\n\n'
        '> **理论看懂了？在自建样本上亲手走一遍对应的缺陷模式。**\n\n'
        '| 命中模式 | 模式名称 | 靶场点位文档 |\n'
        '|:---:|:---|:---|\n'
        + '\n'.join(rows) + '\n\n'
        '**靶场使用方式**：\n\n'
        '```powershell\n'
        'cd docs\\05-教学靶场\n'
        'powershell -ExecutionPolicy Bypass -File .\\build.ps1   # 零依赖编译\n'
        '.\\SeepLab.exe <模式编号>                                 # 运行对应模式\n'
        '```\n\n'
        '> 💡 靶场点位文档针对**自建样本**，可任意修改与分发，\n'
        '> 其中包含**完整偏移、原始字节、修补字节**与**源码行对照**，\n'
        '> 以及**软件归属对照表**（本产品在该模式下的设计层表现）。\n'
    )

    # 插到「## 参考」之前；若无则追加到末尾
    idx = t.rfind('\n---\n\n## 参考')
    if idx < 0:
        idx = t.rfind('## 参考')
        idx = t.rfind('\n---\n\n', 0, idx) if idx > 0 else -1
    if idx > 0:
        t = t[:idx] + section + t[idx:]
    else:
        t = t.rstrip() + '\n' + section

    io.open(fp, 'w', encoding='utf-8', newline='\n').write(t)
    count += 1
    print('[+] %-24s 主模式 %s  命中模式: %s' % (fn, primary, ', '.join(PAT[p][0] for p in pats)))

print('\n[+] 共为 %d 份公告添加「动手实践」交叉引用' % count)
