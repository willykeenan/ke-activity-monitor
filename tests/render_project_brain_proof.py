"""Render deterministic 960x680 source proof for the Project Brain UI.

This script uses only synthetic metadata. It never reads the user's live Brain,
provider stores, project paths, or conversation bodies.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import activity_monitor


def fixture() -> tuple[dict, dict]:
    parent_id = "brain_parent_fixture"
    children = []
    brains = [
        {
            "id": parent_id,
            "label": "KE Studios Brain",
            "type": "KE Desktop brain",
            "path": "/fixture/brain",
            "pathDisplay": "~/.grokcode/brain",
            "status": "connected",
            "canBrowse": True,
            "canConnect": False,
            "canStructure": False,
            "evidence": ["canonical KE Brain", ".obsidian"],
            "countState": "bounded",
        }
    ]
    names = [
        ("Activity Monitor", "codex"),
        ("KE Swarm", "codex"),
        ("Orchard API", "codex"),
        ("Pixel Forge", "codex"),
        ("KE Platform", "codex"),
        ("Career Command Center", "codex"),
        ("Email Agent", "codex"),
        ("Movement Research", "codex"),
        ("Game Studio", "codex"),
        ("Defense Plus", "claude"),
        ("Claude Research", "claude"),
        ("Media Production", "claude"),
    ]
    for index, (name, provider) in enumerate(names):
        brain_id = f"brain_project_fixture_{index:02d}"
        project_id = (
            f"local-{index + 1:032x}"
            if provider == "codex"
            else f"claude-{index + 1:024x}"
        )
        lifecycle = "dormant" if index in {8, 11} else "active"
        child = {
            "brainId": brain_id,
            "parentBrainId": parent_id,
            "projectId": project_id,
            "provider": provider,
            "label": name,
            "lifecycleState": lifecycle,
            "status": "ready",
            "accessible": True,
            "path": f"/fixture/brain/GrokCode/Projects/project-{index:02d}",
            "pathDisplay": f"~/.grokcode/brain/GrokCode/Projects/project-{index:02d}",
        }
        children.append(child)
        brains.append(
            {
                "id": brain_id,
                "label": name,
                "type": "Project Brain",
                "path": child["path"],
                "pathDisplay": child["pathDisplay"],
                "status": "connected",
                "canBrowse": True,
                "canConnect": False,
                "canStructure": False,
                "managedProjectChild": True,
                "parentBrainId": parent_id,
                "projectId": project_id,
                "provider": provider,
                "projectBrainLifecycle": lifecycle,
                "evidence": ["Activity Monitor project registry", ".obsidian"],
                "countState": "complete",
                "itemCount": 6,
            }
        )
    brains.extend([
        {
            "id": "brain_fixture_connect",
            "label": "Research Vault",
            "type": "Obsidian vault",
            "path": "/fixture/research",
            "pathDisplay": "~/Documents/Research Vault",
            "status": "discovered",
            "canBrowse": False,
            "canConnect": True,
            "canStructure": True,
            "evidence": [".obsidian", "verified root"],
            "countState": "complete",
            "itemCount": 12,
        },
        {
            "id": "brain_fixture_repair",
            "label": "Claude Memory",
            "type": "Claude memory",
            "path": "/fixture/claude-memory",
            "pathDisplay": "~/.claude/projects/example/memory",
            "status": "permission-denied",
            "permissionDenied": True,
            "canBrowse": False,
            "canConnect": False,
            "canStructure": False,
            "evidence": ["managed memory registration"],
            "countState": "unavailable",
        },
        {
            "id": "brain_fixture_retry",
            "label": "Archive Brain",
            "type": "Connected brain",
            "path": "/fixture/archive",
            "pathDisplay": "~/Archive Brain",
            "status": "offline",
            "canBrowse": False,
            "canConnect": True,
            "canStructure": False,
            "evidence": ["saved connection"],
            "countState": "unavailable",
        },
    ])
    hierarchy = {
        "ok": True,
        "parent": {
            "brainId": parent_id,
            "label": "KE Studios Brain",
            "path": "/fixture/brain",
            "pathDisplay": "~/.grokcode/brain",
        },
        "children": children,
        "counts": {"total": len(children), "active": 10, "dormant": 2, "blocked": 0},
        "registryRevision": "project_brains_fixture",
        "privacy": {"projectMetadataOnly": True, "automaticDeletion": False},
    }
    inventory = {
        "ok": True,
        "schemaVersion": "ke.activity-monitor-brains.v1",
        "inventoryRevision": "inventory_fixture",
        "brains": brains,
        "summary": {
            "found": len(brains),
            "connected": 13,
            "discovered": 1,
            "projectChildren": len(children),
            "activeProjectChildren": 10,
            "dormantProjectChildren": 2,
        },
        "projectHierarchy": hierarchy,
        "scan": {"directoriesInspected": 1517, "truncated": False},
        "privacy": {"noteBodiesRead": False},
    }
    projects = []
    for index, child in enumerate(children):
        conversation_id = f"01a020e9-{index:04x}-7fb2-a6f5-{index + 1:012x}"
        projects.append(
            {
                "id": child["projectId"],
                "provider": child["provider"],
                "name": child["label"],
                "saved": True,
                "pinned": index < 2,
                "expanded": index == 0,
                "conversationCount": 1,
                "activeCount": 1 if index < 3 else 0,
                "brainId": child["brainId"],
                "parentBrainId": parent_id,
                "brainStatus": "ready",
                "brainLifecycleState": child["lifecycleState"],
                "conversations": [
                    {
                        "id": conversation_id,
                        "provider": child["provider"],
                        "title": f"{child['label']} implementation",
                        "state": "active" if index < 3 else "idle",
                        "stateSource": "provider metadata",
                        "depth": 0,
                        "pinned": index == 0,
                        "canOpen": True,
                        "openLabel": "Open exact conversation",
                        "brainId": child["brainId"],
                    }
                ],
            }
        )
    workspace = {
        "ok": True,
        "projects": projects,
        "availableCodexProjects": [],
        "availableClaudeProjects": [],
        "counts": {"projects": len(projects), "conversations": len(projects), "active": 3},
        "companions": {
            "codex": {"exactOpenAvailable": True},
            "claude": {"exactOpenAvailable": True},
        },
        "preferences": {
            "providerFilters": {"codex": True, "claude": True},
            "railCollapsed": False,
            "railWidth": 252,
            "expandedProjectIds": [projects[0]["id"]],
            "lastSelected": None,
        },
        "warnings": [],
    }
    return inventory, workspace


async def render(output_dir: Path) -> dict:
    inventory, workspace = fixture()
    output_dir.mkdir(parents=True, exist_ok=True)
    visual_path = output_dir / "project-brain-visual-960x680.png"
    selected_visual_path = output_dir / "project-brain-selected-visual-960x680.png"
    loading_visual_path = output_dir / "project-brain-loading-visual-960x680.png"
    direct_states_path = output_dir / "project-brain-direct-states-960x680.png"
    files_path = output_dir / "project-brain-files-960x680.png"
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        )
        page = await browser.new_page(viewport={"width": 960, "height": 680}, device_scale_factor=1)
        await page.emulate_media(reduced_motion="reduce")
        await page.set_content(activity_monitor.HTML, wait_until="domcontentloaded")
        await page.evaluate(
            """fixture => {
                window.pywebview = {api: {
                    list_brain_directory: async (brainId, revision, relativePath) => {
                        if (brainId.endsWith('_00') && window.keHoldFirstBrainRequest) {
                            await new Promise(resolve => { window.keReleaseFirstBrainRequest = resolve; });
                        } else {
                            const delay = brainId.endsWith('_00') ? 80 : 4;
                            await new Promise(resolve => setTimeout(resolve, delay));
                        }
                        const brain = fixture.inventory.brains.find(item => item.id === brainId);
                        return JSON.stringify({
                            ok:true, brainId, inventoryRevision:revision,
                            brainLabel:brain?.label || 'Project Brain', relativePath:relativePath || '',
                            parentPath:relativePath ? '' : null, page:0, hasPrevious:false, hasMore:false,
                            countState:'complete', itemCount:6, breadcrumbs:relativePath
                              ? [{label:brain?.label || 'Brain',relativePath:''},{label:relativePath,relativePath}]
                              : [{label:brain?.label || 'Brain',relativePath:''}],
                            items:[
                                {name:'Inbox',kind:'folder',relativePath:'Inbox',openable:true},
                                {name:'Decisions',kind:'folder',relativePath:'Decisions',openable:true},
                                {name:'Reference',kind:'folder',relativePath:'Reference',openable:true},
                                {name:'Sessions',kind:'folder',relativePath:'Sessions',openable:true},
                                {name:'Project Brain.md',kind:'file',relativePath:'Project Brain.md',openable:true,sizeBytes:612},
                            ],
                        });
                    },
                    open_brain_note: async (brainId, revision, relativePath) => {
                        const brain = fixture.inventory.brains.find(item => item.id === brainId);
                        return JSON.stringify({
                            ok:true, brainId, inventoryRevision:revision,
                            brainLabel:brain?.label || 'Project Brain', relativePath,
                            parentPath:'', sizeBytes:612, modifiedAt:'2026-08-21T04:00:00Z',
                            breadcrumbs:[{label:brain?.label || 'Brain',relativePath:''},{label:relativePath,relativePath}],
                            body:'# Project Brain\\n\\nGoverned child of the canonical KE Studios Brain.',
                        });
                    },
                }};
                apiReady = true;
                currentTab = 'brain';
                document.querySelectorAll('.seg-btn').forEach(button => button.classList.toggle('active', button.dataset.tab === 'brain'));
                document.querySelectorAll('.tab-content').forEach(tab => tab.classList.toggle('active', tab.id === 'brain-tab'));
                workspaceSnapshot = fixture.workspace;
                workspaceExpanded = new Set(fixture.workspace.preferences.expandedProjectIds || []);
                workspaceApplyPreferences(fixture.workspace.preferences);
                renderWorkspace(fixture.workspace);
                lastBrainInventory = fixture.inventory;
                renderBrain(fixture.inventory);
                setBrainView('files');
            }""",
            {"inventory": inventory, "workspace": workspace},
        )
        await page.wait_for_selector("#brain-files-browser-host .brain-item")
        files_layout = await page.evaluate("""() => {
          const workspace=document.getElementById('brain-files-view').getBoundingClientRect();
          const sidebar=document.getElementById('brain-list').getBoundingClientRect();
          const browser=document.getElementById('brain-browser').getBoundingClientRect();
          const privacy=document.getElementById('brain-privacy-copy').getBoundingClientRect();
          const summaries=Array.from(document.querySelectorAll('#brain-tab .brain-overview small,#brain-tab .brain-family-copy,#brain-tab .brain-child-copy span'));
          return {
            workspaceTop:workspace.top,
            workspaceHeight:workspace.height,
            sidebarWidth:sidebar.width,
            browserTop:browser.top,
            browserItemCount:document.querySelectorAll('#brain-files-browser-host .brain-item').length,
            privacyHeight:privacy.height,
            equalKpiTileCount:document.querySelectorAll('#brain-tab .feature-summary .summary-tile').length,
            truncatedSummaryCount:summaries.filter(node => node.scrollWidth > node.clientWidth + 1).length,
            browserVisible:!document.getElementById('brain-browser').hidden,
          };
        }""")
        await page.screenshot(path=str(files_path))
        direct_actions = await page.locator(".brain-primary-action").all_text_contents()
        await page.locator('.brain-card[data-brain-id="brain_fixture_connect"]').scroll_into_view_if_needed()
        await page.screenshot(path=str(direct_states_path))
        await page.evaluate("closeBrainBrowser(); document.querySelector('#brain-tab .feature-scroll').scrollTop = 0")
        forbidden_copy_count = await page.get_by_text("Why unavailable", exact=False).count()
        brain_microcopy = await page.evaluate("""() => Array.from(document.querySelectorAll('#brain-tab *')).filter(node => {
          const style=getComputedStyle(node); const rect=node.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0 && node.childElementCount === 0 && node.textContent.trim() && parseFloat(style.fontSize) < 10;
        }).map(node => ({text:node.textContent.trim().slice(0,80),size:getComputedStyle(node).fontSize}))""")
        await page.click("#brain-view-visual")
        await page.click("#brain-visual-zoom-in")
        zoomed = await page.get_attribute("#brain-graph-world", "transform")
        await page.click("#brain-visual-fit")
        fitted = await page.get_attribute("#brain-graph-world", "transform")
        visual_layout = await page.evaluate("""() => {
          const visible = node => {
            const style=getComputedStyle(node); const rect=node.getBoundingClientRect();
            return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
          };
          const nodes=Array.from(document.querySelectorAll('.brain-graph-node'));
          const children=nodes.filter(node => !node.classList.contains('parent'));
          const bounds=children.map(node => ({node,rect:node.getBoundingClientRect()}));
          let collisions=0;
          for (let left=0; left<bounds.length; left += 1) {
            for (let right=left+1; right<bounds.length; right += 1) {
              const a=bounds[left].rect,b=bounds[right].rect;
              if (Math.min(a.right,b.right)-Math.max(a.left,b.left)>2 && Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>2) collisions += 1;
            }
          }
          const groups=children.reduce((result,node) => {
            const group=node.dataset.spatialGroup || 'unassigned';
            result[group]=(result[group] || 0)+1;
            return result;
          },{});
          const fills=children.map(node => getComputedStyle(node.querySelector('rect')).fill);
          const labels=Array.from(document.querySelectorAll('.brain-region-label')).map(node => node.textContent.trim());
          const truncatedNodeLabels=children.map(node => ({
            expected:(node.querySelector('title')?.textContent || '').split(' · ')[0],
            rendered:Array.from(node.querySelectorAll('.brain-graph-label tspan')).map(span => span.textContent).join(' '),
          })).filter(item => item.rendered.includes('…') || item.rendered !== item.expected);
          return {
            spatialLayers:document.querySelectorAll('.brain-spatial-layer').length,
            regions:document.querySelectorAll('.brain-region').length,
            folds:document.querySelectorAll('.brain-fold').length,
            bridges:document.querySelectorAll('.brain-bridge').length,
            orbits:document.querySelectorAll('.brain-orbit').length,
            nodeSignals:document.querySelectorAll('.brain-node-signal').length,
            synapses:document.querySelectorAll('.brain-synapse').length,
            cubicEdges:Array.from(document.querySelectorAll('.brain-graph-edge')).filter(edge => / C /.test(edge.getAttribute('d') || '')).length,
            groups,
            regionLabels:labels,
            collisions,
            whiteNodeSurfaces:fills.filter(fill => /247, 251, 255|255, 244, 237|247, 241, 230/.test(fill)).length,
            truncatedNodeLabels,
            visibleTextBelow10:Array.from(document.querySelectorAll('#brain-visual text,#brain-visual button,#brain-visual div')).filter(node => visible(node) && node.textContent.trim() && parseFloat(getComputedStyle(node).fontSize) < 10).map(node => ({text:node.textContent.trim(),size:getComputedStyle(node).fontSize})),
          };
        }""")
        await page.screenshot(path=str(visual_path))

        # Exercise a real graph-node click and selected-note boundary.
        graph_nodes = page.locator(".brain-graph-node:not(.parent)")
        await page.evaluate("window.keHoldFirstBrainRequest = true")
        await graph_nodes.first.click()
        await page.wait_for_selector("#brain-browser:not([hidden])")
        loading_truth = await page.evaluate("""() => ({
          message:document.getElementById('brain-browser-message').textContent,
          messageHidden:document.getElementById('brain-browser-message').hidden,
          directoryHidden:document.getElementById('brain-directory').hidden,
          staleRowCount:document.querySelectorAll('#brain-directory .brain-item').length,
          skeletonRowCount:document.querySelectorAll('#brain-directory .brain-directory-loading-row').length,
          loadingStatusCount:document.querySelectorAll('#brain-directory [role="status"]').length,
        })""")
        await page.screenshot(path=str(loading_visual_path))
        await page.evaluate("""() => {
          window.keHoldFirstBrainRequest = false;
          window.keReleaseFirstBrainRequest?.();
          window.keReleaseFirstBrainRequest = null;
        }""")
        await page.wait_for_selector("#brain-visual-inspector .brain-item")
        visual_open = await page.evaluate("""() => ({
          view:brainView,
          visualHidden:document.getElementById('brain-visual').hidden,
          filesHidden:document.getElementById('brain-files-view').hidden,
          visualSelected:document.getElementById('brain-view-visual').getAttribute('aria-selected'),
          inspectorHidden:document.getElementById('brain-visual-inspector').hidden,
          browserParent:document.getElementById('brain-browser').parentElement.id
        })""")
        await page.screenshot(path=str(selected_visual_path))
        await page.locator(".brain-item").filter(has_text="Inbox").click()
        await page.wait_for_function("brainBrowserState?.relativePath === 'Inbox'")
        folder_stayed_visual = await page.evaluate("brainView === 'visual' && !document.getElementById('brain-visual-inspector').hidden")
        await page.click("#brain-browser-back")
        await page.wait_for_function("brainBrowserState?.view === 'directory' && brainBrowserState?.relativePath === ''")
        await page.locator(".brain-item").filter(has_text="Project Brain.md").click()
        await page.wait_for_selector("#brain-note:not([hidden])")
        note_open = await page.text_content("#brain-bodies")
        await page.click("#brain-browser-back")
        await page.wait_for_function("brainBrowserState?.view === 'directory' && brainBrowserState?.relativePath === ''")
        note_back = await page.evaluate(
            """() => ({
                view: brainView,
                visualHidden: document.getElementById('brain-visual').hidden,
                browserHidden: document.getElementById('brain-browser').hidden,
                noteHidden: document.getElementById('brain-note').hidden,
                noteBody: document.getElementById('brain-note-body').textContent,
                bodyIndicator: document.getElementById('brain-bodies').textContent,
            })"""
        )
        await page.click("#brain-browser-back")
        await page.wait_for_function("Boolean(document.activeElement?.dataset?.brainId)")
        visual_back = await page.evaluate("""() => ({
          view:brainView,
          browserHidden:document.getElementById('brain-browser').hidden,
          inspectorHidden:document.getElementById('brain-visual-inspector').hidden,
          focusedBrainId:document.activeElement?.dataset?.brainId || '',
          noteBody:document.getElementById('brain-note-body').textContent
        })""")

        await graph_nodes.nth(1).focus()
        await graph_nodes.nth(1).press("Enter")
        await page.wait_for_selector("#brain-browser:not([hidden])")
        keyboard_enter_stayed_visual = await page.evaluate("brainView === 'visual' && !document.getElementById('brain-visual-inspector').hidden")
        await page.click("#brain-browser-close")
        await graph_nodes.nth(2).focus()
        await graph_nodes.nth(2).press("Space")
        await page.wait_for_selector("#brain-browser:not([hidden])")
        keyboard_space_stayed_visual = await page.evaluate("brainView === 'visual' && !document.getElementById('brain-visual-inspector').hidden")

        # A delayed A result must not overwrite the later B selection.
        race_title = await page.evaluate(
            """async fixture => {
                closeBrainBrowser();
                setBrainView('files');
                const first = fixture.inventory.brains.find(item => item.id === 'brain_project_fixture_00');
                const second = fixture.inventory.brains.find(item => item.id === 'brain_project_fixture_01');
                const a = activateBrainCard(first);
                const b = activateBrainCard(second);
                await Promise.allSettled([a, b]);
                return document.getElementById('brain-browser-title').textContent;
            }""",
            {"inventory": inventory},
        )
        await browser.close()
    if forbidden_copy_count:
        raise RuntimeError("removed Brain explainer copy is still visible")
    if not {"Connect & open", "Repair access", "Retry"}.issubset(set(direct_actions)):
        raise RuntimeError("Brain direct-action states are incomplete")
    if brain_microcopy:
        raise RuntimeError(f"Brain has visible text below 10px: {brain_microcopy[:4]}")
    if not all((
        visual_layout["spatialLayers"] == 1,
        visual_layout["regions"] == 2,
        visual_layout["folds"] == 6,
        visual_layout["bridges"] == 1,
        visual_layout["orbits"] == 2,
        visual_layout["nodeSignals"] == 13,
        visual_layout["synapses"] == 12,
        visual_layout["cubicEdges"] == 12,
        visual_layout["groups"] == {"codex": 8, "dormant": 2, "claude": 2},
        visual_layout["regionLabels"] == ["Claude projects", "Codex projects", "Dormant"],
        visual_layout["collisions"] == 0,
        visual_layout["whiteNodeSurfaces"] == 0,
        not visual_layout["truncatedNodeLabels"],
        not visual_layout["visibleTextBelow10"],
    )):
        raise RuntimeError(f"Brain Visual is not a layered, readable spatial map: {visual_layout}")
    if not all((
        loading_truth["messageHidden"],
        loading_truth["message"] == "",
        not loading_truth["directoryHidden"],
        loading_truth["staleRowCount"] == 0,
        loading_truth["skeletonRowCount"] == 5,
        loading_truth["loadingStatusCount"] == 1,
    )):
        raise RuntimeError(f"Brain Visual retained stale rows beside loading truth: {loading_truth}")
    if not all((
        files_layout["browserVisible"],
        files_layout["browserItemCount"] >= 5,
        files_layout["workspaceTop"] < 210,
        files_layout["workspaceHeight"] >= 400,
        200 <= files_layout["sidebarWidth"] <= 280,
        abs(files_layout["browserTop"] - files_layout["workspaceTop"]) <= 2,
        files_layout["privacyHeight"] <= 32,
        files_layout["equalKpiTileCount"] == 0,
        files_layout["truncatedSummaryCount"] == 0,
    )):
        raise RuntimeError(f"Brain Files is not a compact Finder-style workspace: {files_layout}")
    if not all((
        visual_open["view"] == "visual",
        not visual_open["visualHidden"],
        visual_open["filesHidden"],
        visual_open["visualSelected"] == "true",
        not visual_open["inspectorHidden"],
        visual_open["browserParent"] == "brain-visual-inspector",
        folder_stayed_visual,
        keyboard_enter_stayed_visual,
        keyboard_space_stayed_visual,
    )):
        raise RuntimeError("Visual Brain navigation changed mode or lost its inspector")
    if note_back["view"] != "visual" or note_back["browserHidden"] or not note_back["noteHidden"] or note_back["noteBody"]:
        raise RuntimeError("Note Back did not return to the visual folder safely")
    if (
        visual_back["view"] != "visual"
        or not visual_back["browserHidden"]
        or not visual_back["inspectorHidden"]
        or not visual_back["focusedBrainId"]
        or visual_back["noteBody"]
    ):
        raise RuntimeError(f"Visual Back did not restore the constellation and deterministic focus: {visual_back}")
    report = {
        "contract": "ke.activity-monitor-brain-product-first-look.v1",
        "sourceOnly": True,
        "installedAppMutated": False,
        "ok": True,
        "viewport": "960x680",
        "files": str(files_path),
        "filesSha256": hashlib.sha256(files_path.read_bytes()).hexdigest(),
        "visual": str(visual_path),
        "visualSha256": hashlib.sha256(visual_path.read_bytes()).hexdigest(),
        "selectedVisual": str(selected_visual_path),
        "selectedVisualSha256": hashlib.sha256(selected_visual_path.read_bytes()).hexdigest(),
        "loadingVisual": str(loading_visual_path),
        "loadingVisualSha256": hashlib.sha256(loading_visual_path.read_bytes()).hexdigest(),
        "directStates": str(direct_states_path),
        "directStatesSha256": hashlib.sha256(direct_states_path.read_bytes()).hexdigest(),
        "zoomedTransform": zoomed,
        "fittedTransform": fitted,
        "selectedNoteIndicator": note_open,
        "directActions": direct_actions,
        "forbiddenCopyCount": forbidden_copy_count,
        "visibleTextBelow10px": brain_microcopy,
        "filesLayout": files_layout,
        "visualOpen": visual_open,
        "visualLayout": visual_layout,
        "loadingTruth": loading_truth,
        "folderStayedVisual": folder_stayed_visual,
        "noteBack": note_back,
        "visualBack": visual_back,
        "keyboardEnterStayedVisual": keyboard_enter_stayed_visual,
        "keyboardSpaceStayedVisual": keyboard_space_stayed_visual,
        "raceWinner": race_title,
        "fixtureProjectBrains": len(inventory["projectHierarchy"]["children"]),
    }
    report_path = output_dir / "project-brain-source-proof.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["report"] = str(report_path)
    report["reportSha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(render(args.output_dir)), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
