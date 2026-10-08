import {Compartment, EditorState, EditorSelection} from "@codemirror/state";
import {EditorView, ViewPlugin, Decoration, keymap, lineNumbers, highlightActiveLineGutter, highlightSpecialChars,
  drawSelection, dropCursor, rectangularSelection, crosshairCursor, highlightActiveLine,
  highlightWhitespace, highlightTrailingWhitespace} from "@codemirror/view";
import {indentUnit, indentOnInput, bracketMatching, foldGutter, foldKeymap,
  syntaxHighlighting, syntaxTree, HighlightStyle} from "@codemirror/language";
import {defaultKeymap, history, historyKeymap, indentMore, indentLess, indentSelection,
  insertTab, toggleComment, undo, redo, undoDepth, redoDepth} from "@codemirror/commands";
import {search, searchKeymap, highlightSelectionMatches, openSearchPanel, gotoLine,
  selectNextOccurrence} from "@codemirror/search";
import {autocompletion, completionKeymap, closeBrackets, closeBracketsKeymap,
  acceptCompletion, completionStatus, snippetCompletion} from "@codemirror/autocomplete";
import {python} from "@codemirror/lang-python";
import {cpp} from "@codemirror/lang-cpp";
import {tags} from "@lezer/highlight";

const colors = HighlightStyle.define([
  {tag: tags.keyword, class: "syntax-keyword"},
  {tag: [tags.definitionKeyword, tags.moduleKeyword], class: "syntax-definition"},
  {tag: [tags.function(tags.variableName), tags.function(tags.definition(tags.variableName))], class: "syntax-function"},
  {tag: [tags.typeName, tags.className, tags.namespace], class: "syntax-type"},
  {tag: [tags.string, tags.character], class: "syntax-string"},
  {tag: [tags.escape, tags.special(tags.string)], class: "syntax-escape"},
  {tag: [tags.number, tags.bool, tags.null], class: "syntax-number"},
  {tag: [tags.comment, tags.docComment], class: "syntax-comment"},
  {tag: [tags.operator, tags.operatorKeyword], class: "syntax-operator"},
  {tag: [tags.meta, tags.annotation, tags.processingInstruction], class: "syntax-meta"},
  {tag: [tags.propertyName, tags.attributeName], class: "syntax-property"},
  {tag: tags.special(tags.variableName), class: "syntax-builtin"},
  {tag: tags.punctuation, class: "syntax-punctuation"}
]);

const phrases = {
  "Control character": "Caractère de contrôle", "Fold line": "Replier le bloc", "Unfold line": "Déplier le bloc",
  "Folded lines": "Lignes repliées", "Unfold": "Déplier", "Go to line": "Aller à la ligne",
  "go": "Aller", "Find": "Rechercher", "Replace": "Remplacer", "next": "Suivant",
  "previous": "Précédent", "all": "Tout sélectionner", "match case": "Respecter la casse",
  "regexp": "Expression régulière", "by word": "Mot entier", "replace": "Remplacer",
  "replace all": "Tout remplacer", "close": "Fermer", "Search": "Recherche",
  "No matches": "Aucun résultat", "No matches found": "Aucun résultat",
  "Selection deleted": "Sélection supprimée", "Completions": "Suggestions",
  "Diagnostics": "Diagnostics", "At end of document": "Fin du document", "At start of document": "Début du document"
};

const snippets = {
  python: [
    ["def", "Fonction", "def ${nom}(${arguments}):\n\t${pass}"],
    ["class", "Classe", "class ${Nom}:\n\tdef __init__(self${}):\n\t\t${pass}"],
    ["for", "Boucle for", "for ${element} in ${elements}:\n\t${pass}"],
    ["if", "Condition", "if ${condition}:\n\t${pass}"],
    ["try", "Gestion d’exception", "try:\n\t${pass}\nexcept ${Exception} as ${erreur}:\n\t${pass}"],
    ["main", "Point d’entrée", 'if __name__ == "__main__":\n\t${main()}']
  ],
  c: [
    ["for", "Boucle for", "for (int ${i} = 0; ${i} < ${n}; ${i}++) {\n\t${}\n}"],
    ["if", "Condition", "if (${condition}) {\n\t${}\n}"],
    ["while", "Boucle while", "while (${condition}) {\n\t${}\n}"],
    ["main", "Point d’entrée", "int main(void) {\n\t${}\n\treturn 0;\n}"],
    ["struct", "Structure", "struct ${Nom} {\n\t${}\n};"]
  ]
};
const cWords = "auto break case char const continue default do double else enum extern float for goto if inline int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile while _Bool _Complex _Atomic size_t NULL EOF printf fprintf snprintf scanf puts putchar getchar fgets fopen fclose malloc calloc realloc free memcpy memmove memset strlen strcmp strcpy exit abs".split(" ");

const indentationGuides = ViewPlugin.fromClass(class {
  constructor(view) {this.decorations = this.build(view);}
  update(update) {
    if (update.docChanged || update.viewportChanged || update.startState.tabSize !== update.state.tabSize) this.decorations = this.build(update.view);
  }
  build(view) {
    const ranges = [], width = view.state.tabSize;
    const marker = Decoration.mark({class: "cm-indent-guide"});
    for (const visible of view.visibleRanges) {
      for (let pos = visible.from; pos <= visible.to;) {
        const line = view.state.doc.lineAt(pos), prefix = line.text.match(/^[\t ]*/)[0];
        let from = 0, column = 0;
        for (let i = 0; i < prefix.length && column < 256; i++) {
          column += prefix[i] === "\t" ? width - column % width : 1;
          if (column % width === 0) {ranges.push(marker.range(line.from + from, line.from + i + 1)); from = i + 1;}
        }
        pos = line.to + 1;
      }
    }
    return Decoration.set(ranges, true);
  }
}, {decorations: value => value.decorations});

function indentation(text) {
  const lines = text.split("\n").filter(line => /\S/.test(line));
  const indents = lines.map(line => line.match(/^[\t ]*/)[0]).filter(Boolean);
  if (indents.filter(value => value[0] === "\t").length > indents.length / 2) return "\t";
  // Use the smallest observed indentation, so a file beginning inside a block
  // does not mistake a nested block for a one-level change.
  const widths = indents.filter(value => /^ +$/.test(value)).map(value => value.length);
  const width = widths.length ? Math.min(...widths) : 4;
  return " ".repeat([2, 4, 8].includes(width) ? width : 4);
}

export function createCode({host, isPython, onChange, onSave, onRun}) {
  const $ = id => document.getElementById(id);
  const readOnly = new Compartment(), indent = new Compartment(), wrapping = new Compartment(), theme = new Compartment(), whitespace = new Compartment();
  let unit = "    ", editable = false, view;
  // CodeMirror supports ShadowRoot directly. Its constructable stylesheets keep
  // styles isolated and work with style-src 'self', without an inline exception.
  const root = host.attachShadow({mode: "open"});
  const stylesheet = document.createElement("link");
  stylesheet.rel = "stylesheet"; stylesheet.href = "/editor.css"; root.append(stylesheet);
  const templates = snippets[isPython ? "python" : "c"].map(([label, detail, template]) =>
    snippetCompletion(template, {label, detail, type: "text", boost: -1}));
  function complete(context) {
    const node = syntaxTree(context.state).resolveInner(context.pos, -1);
    if (/String|Comment/.test(node.name)) return null;
    const word = context.matchBefore(/[A-Za-z_]\w*/);
    if (!word && !context.explicit) return null;
    return {from: word ? word.from : context.pos, options: [...templates,
      ...(isPython ? [] : cWords.map(label => ({label, type: /^(printf|puts|malloc|free|fopen)/.test(label) ? "function" : "keyword"})))], validFor: /^\w*$/};
  }
  const tab = editor => {
    if (editor.state.readOnly) return false;
    if (completionStatus(editor.state) === "active" && acceptCompletion(editor)) return true;
    if (editor.state.selection.ranges.some(range => !range.empty)) return indentMore(editor);
    if (unit === "\t") return insertTab(editor);
    const changes = editor.state.changeByRange(range => {
      const column = range.head - editor.state.doc.lineAt(range.head).from;
      const spaces = " ".repeat(unit.length - column % unit.length);
      return {changes: {from: range.from, to: range.to, insert: spaces}, range: EditorSelection.cursor(range.from + spaces.length)};
    });
    editor.dispatch({...changes, scrollIntoView: true, userEvent: "input.indent"});
    return true;
  };
  function status() {
    const state = view.state, selection = state.selection.main, line = state.doc.lineAt(selection.head);
    const count = state.selection.ranges.reduce((total, range) => total + range.to - range.from, 0);
    $("editor-position").textContent = `Ln ${line.number}, Col ${selection.head - line.from + 1}${count ? ` · ${count} car. sélectionnés` : ""}${state.selection.ranges.length > 1 ? ` · ${state.selection.ranges.length} curseurs` : ""}`;
    $("editor-lines").textContent = `${state.doc.lines} ligne${state.doc.lines > 1 ? "s" : ""}`;
    $("editor-undo").disabled = !editable || undoDepth(state) === 0;
    $("editor-redo").disabled = !editable || redoDepth(state) === 0;
    $("editor-reindent").disabled = !editable;
  }
  const extensions = () => [
    lineNumbers(), highlightActiveLineGutter(), highlightSpecialChars(), history(),
    drawSelection(), dropCursor(), rectangularSelection(), crosshairCursor(), highlightActiveLine(),
    EditorState.allowMultipleSelections.of(true), EditorState.phrases.of(phrases),
    indentOnInput(), bracketMatching(), foldGutter(), syntaxHighlighting(colors), indentationGuides,
    closeBrackets(), autocompletion({activateOnTyping: true}),
    isPython ? python() : cpp(), EditorState.languageData.of(() => [{autocomplete: complete}]),
    search({top: true}), highlightSelectionMatches(),
    indent.of([indentUnit.of(unit), EditorState.tabSize.of(unit === "\t" ? 4 : unit.length)]),
    wrapping.of($("editor-wrap").getAttribute("aria-pressed") === "true" ? EditorView.lineWrapping : []),
    whitespace.of($("editor-whitespace").getAttribute("aria-pressed") === "true" ? [highlightWhitespace(), highlightTrailingWhitespace()] : []),
    readOnly.of([EditorState.readOnly.of(!editable), EditorView.editable.of(editable)]),
    theme.of(EditorView.theme({}, {dark: document.documentElement.dataset.theme === "dark"})),
    EditorView.contentAttributes.of({id: "code-input", tabindex: "0", "aria-label": "Code source", "aria-describedby": "code-keyboard-help", spellcheck: "false", autocapitalize: "off", autocorrect: "off"}),
    keymap.of([
      {key: "Mod-s", run: () => {onSave(); return true;}},
      {key: "Mod-Shift-z", run: redo, preventDefault: true},
      {key: "Mod-Enter", run: () => {onRun(); return true;}},
      {key: "Tab", run: tab, shift: indentLess},
      {key: "Mod-d", run: selectNextOccurrence, preventDefault: true},
      {key: "Mod-/", run: toggleComment},
      {key: "Mod-h", run: openSearchPanel, preventDefault: true},
      {key: "Mod-g", run: gotoLine, preventDefault: true},
      {key: "Mod-Shift-i", run: indentSelection},
      ...closeBracketsKeymap, ...defaultKeymap, ...searchKeymap, ...historyKeymap, ...foldKeymap, ...completionKeymap
    ]),
    EditorView.updateListener.of(update => {
      if (update.docChanged) onChange();
      if (update.docChanged || update.selectionSet || update.transactions.length) status();
    })
  ];
  view = new EditorView({parent: root, root, state: EditorState.create({extensions: extensions()})});
  view.scrollDOM.id = "code-scroll";
  const help = document.createElement("span"); help.id = "code-keyboard-help"; help.className = "sr-only";
  help.textContent = "Tab pour indenter. Échap puis Tab pour sortir de l’éditeur. Ctrl Espace pour les suggestions. Ctrl F pour rechercher.";
  root.append(help);
  new MutationObserver(() => view.dispatch({effects: theme.reconfigure(EditorView.theme({}, {dark: document.documentElement.dataset.theme === "dark"}))}))
    .observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
  for (const [id, command] of [["editor-undo", undo], ["editor-redo", redo], ["editor-find", openSearchPanel], ["editor-goto", gotoLine], ["editor-reindent", indentSelection]]) {
    $(id).addEventListener("click", () => {view.focus(); command(view);});
  }
  $("editor-wrap").addEventListener("click", () => {
    const enabled = $("editor-wrap").getAttribute("aria-pressed") !== "true";
    $("editor-wrap").setAttribute("aria-pressed", String(enabled));
    view.dispatch({effects: wrapping.reconfigure(enabled ? EditorView.lineWrapping : [])});
  });
  $("editor-whitespace").addEventListener("click", () => {
    const enabled = $("editor-whitespace").getAttribute("aria-pressed") !== "true";
    $("editor-whitespace").setAttribute("aria-pressed", String(enabled));
    view.dispatch({effects: whitespace.reconfigure(enabled ? [highlightWhitespace(), highlightTrailingWhitespace()] : [])});
  });
  $("editor-indent").addEventListener("change", () => {
    unit = $("editor-indent").value === "tab" ? "\t" : " ".repeat(Number($("editor-indent").value));
    view.dispatch({effects: indent.reconfigure([indentUnit.of(unit), EditorState.tabSize.of(unit === "\t" ? 4 : unit.length)])});
    view.focus();
  });
  status();
  return {
    get value() {return view.state.doc.toString();},
    set value(text) {
      unit = indentation(text);
      $("editor-indent").value = unit === "\t" ? "tab" : String(unit.length);
      // Loading a different revision resets undo, preventing access to an old
      // document after logout and keeping the initial load out of save events.
      view.setState(EditorState.create({doc: text, extensions: extensions()})); status();
    },
    set readOnly(value) {editable = !value; if (view.state.readOnly !== value) view.dispatch({effects: readOnly.reconfigure([EditorState.readOnly.of(value), EditorView.editable.of(!value)])}); status();},
    focus: () => view.focus()
  };
}
