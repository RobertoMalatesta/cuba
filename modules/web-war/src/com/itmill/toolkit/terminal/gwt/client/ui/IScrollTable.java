/*
 * Copyright 2008 IT Mill Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.itmill.toolkit.terminal.gwt.client.ui;

import com.google.gwt.user.client.*;
import com.google.gwt.user.client.Timer;
import com.google.gwt.user.client.ui.*;
import com.itmill.toolkit.terminal.gwt.client.*;
import com.haulmont.cuba.toolkit.gwt.client.Tools;

import java.util.*;

/**
 * IScrollTable
 *
 * IScrollTable is a FlowPanel having two widgets in it: * TableHead component *
 * ScrollPanel
 *
 * TableHead contains table's header and widgets + logic for resizing,
 * reordering and hiding columns.
 *
 * ScrollPanel contains IScrollTableBody object which handles content. To save
 * some bandwidth and to improve clients responsiveness with loads of data, in
 * IScrollTableBody all rows are not necessary rendered. There are "spacers" in
 * IScrollTableBody to use the exact same space as non-rendered rows would use.
 * This way we can use seamlessly traditional scrollbars and scrolling to fetch
 * more rows instead of "paging".
 *
 * In IScrollTable we listen to scroll events. On horizontal scrolling we also
 * update TableHeads scroll position which has its scrollbars hidden. On
 * vertical scroll events we will check if we are reaching the end of area where
 * we have rows rendered and
 *
 * TODO implement unregistering for child components in Cells
 */
public class IScrollTable extends FlowPanel implements Table, ScrollListener {

    public static final String CLASSNAME = "i-table";
    /**
     * multiple of pagelength which component will cache when requesting more
     * rows
     */
    protected static final double CACHE_RATE = 2;
    /**
     * fraction of pageLenght which can be scrolled without making new request
     */
    protected static final double CACHE_REACT_RATE = 1.5;

    public static final char ALIGN_CENTER = 'c';
    public static final char ALIGN_LEFT = 'b';
    public static final char ALIGN_RIGHT = 'e';
    protected int firstRowInViewPort = 0;
    protected int pageLength = 15;
    protected int lastRequestedFirstvisible = 0; // to detect "serverside scroll"

    protected boolean showRowHeaders = false;

    private String[] columnOrder;

    protected ApplicationConnection client;
    protected String paintableId;

    protected boolean immediate;

    protected int selectMode = Table.SELECT_MODE_NONE;

    protected final HashSet selectedRowKeys = new HashSet();

    protected boolean initializedAndAttached = false;

    protected final TableHead tHead = new TableHead();

    protected final ScrollPanel bodyContainer = new ScrollPanel();

    protected int totalRows;

    private Set<String> collapsedColumns;

    protected final RowRequestHandler rowRequestHandler;
    protected IScrollTableBody tBody;
    protected int firstvisible = 0;
    private boolean sortAscending;
    private String sortColumn;
    private boolean columnReordering;

    /**
     * This map contains captions and icon urls for actions like: * "33_c" ->
     * "Edit" * "33_i" -> "http://dom.com/edit.png"
     */
    private final HashMap actionMap = new HashMap();
    private String[] visibleColOrder;
    private boolean initialContentReceived = false;
    private Element scrollPositionElement;
    protected boolean enabled;
    private boolean showColHeaders;

    /** flag to indicate that table body has changed */
    protected boolean isNewBody = true;

    private boolean emitClickEvents;

    /*
     * Read from the "recalcWidths" -attribute. When it is true, the table will
     * recalculate the widths for columns - desirable in some cases. For #1983,
     * marked experimental.
     */
    boolean recalcWidths = false;

    protected int scrollbarWidthReservedInColumn = -1;
    protected int scrollbarWidthReserved = -1;
    protected boolean relativeWidth = false;

    protected int calculatedWidth = -1;

    private final ArrayList lazyUnregistryBag = new ArrayList();
    protected String height;
    protected String width = "";

    protected boolean allowMultiStingCells = false;
    protected boolean nullSelectionDisallowed = false;

    public IScrollTable() {
        bodyContainer.addScrollListener(this);
        bodyContainer.setStyleName(CLASSNAME + "-body");

        setStyleName(CLASSNAME);
        add(tHead);
        add(bodyContainer);

        rowRequestHandler = new RowRequestHandler();

    }

    public void updateFromUIDL(UIDL uidl, ApplicationConnection client) {
        if (client.updateComponent(this, uidl, true)) {
            return;
        }

        if (uidl.hasAttribute("width")) {
            relativeWidth = uidl.getStringAttribute("width").endsWith("%");
        }

        // we may have pending cache row fetch, cancel it. See #2136
        rowRequestHandler.cancel();

        enabled = !uidl.hasAttribute("disabled");

        this.client = client;
        paintableId = uidl.getStringAttribute("id");
        immediate = uidl.getBooleanAttribute("immediate");
        emitClickEvents = uidl.getBooleanAttribute("listenClicks");
        final int newTotalRows = uidl.getIntAttribute("totalrows");
        if (newTotalRows != totalRows) {
            if (tBody != null) {
                if (totalRows == 0) {
                    tHead.clear();
                }
                initializedAndAttached = false;
                initialContentReceived = false;
                isNewBody = true;
            }
            totalRows = newTotalRows;
        }

        recalcWidths = uidl.hasAttribute("recalcWidths");

        pageLength = uidl.getIntAttribute("pagelength");
        if (pageLength == 0) {
            pageLength = totalRows;
        }
        firstvisible = uidl.hasVariable("firstvisible") ? uidl
                .getIntVariable("firstvisible") : 0;
        if (firstvisible != lastRequestedFirstvisible && tBody != null) {
            // received 'surprising' firstvisible from server: scroll there
            firstRowInViewPort = firstvisible;
            bodyContainer
                    .setScrollPosition(firstvisible * tBody.getRowHeight());
        }

        showRowHeaders = uidl.getBooleanAttribute("rowheaders");
        showColHeaders = uidl.getBooleanAttribute("colheaders");
        allowMultiStingCells = uidl.getBooleanAttribute("multistring");
        nullSelectionDisallowed = uidl.getBooleanAttribute("nullSelectionDisallowed");

        if (uidl.hasVariable("sortascending")) {
            sortAscending = uidl.getBooleanVariable("sortascending");
            sortColumn = uidl.getStringVariable("sortcolumn");
        }

        if (uidl.hasVariable("selected")) {
            final Set selectedKeys = uidl
                    .getStringArrayVariableAsSet("selected");
            selectedRowKeys.clear();
            for (final Iterator it = selectedKeys.iterator(); it.hasNext();) {
                selectedRowKeys.add(it.next());
            }
        }

        if (uidl.hasAttribute("selectmode")) {
            if (uidl.getBooleanAttribute("readonly")) {
                selectMode = Table.SELECT_MODE_NONE;
            } else if (uidl.getStringAttribute("selectmode").equals("multi")) {
                selectMode = Table.SELECT_MODE_MULTI;
            } else if (uidl.getStringAttribute("selectmode").equals("single")) {
                selectMode = Table.SELECT_MODE_SINGLE;
            } else {
                selectMode = Table.SELECT_MODE_NONE;
            }
        }

        if (uidl.hasVariable("columnorder")) {
            columnReordering = true;
            columnOrder = uidl.getStringArrayVariable("columnorder");
        }

        if (uidl.hasVariable("collapsedcolumns")) {
            tHead.setColumnCollapsingAllowed(true);
            collapsedColumns = uidl
                    .getStringArrayVariableAsSet("collapsedcolumns");
        } else {
            tHead.setColumnCollapsingAllowed(false);
        }

        UIDL rowData = null;
        for (final Iterator it = uidl.getChildIterator(); it.hasNext();) {
            final UIDL c = (UIDL) it.next();
            if (c.getTag().equals("rows")) {
                rowData = c;
            } else if (c.getTag().equals("actions")) {
                updateActionMap(c);
            } else if (c.getTag().equals("visiblecolumns")) {
                tHead.updateCellsFromUIDL(c);
            }
        }
        updateHeader(uidl.getStringArrayAttribute("vcolorder"));

        if (!recalcWidths && initializedAndAttached) {
            updateBody(rowData, uidl.getIntAttribute("firstrow"), uidl
                    .getIntAttribute("rows"));
        } else {
            if (tBody != null) {
                tBody.removeFromParent();
                lazyUnregistryBag.add(tBody);
            }
            tBody = createBody();
//            tBody.initCols();
            tBody.renderInitialRows(rowData, uidl.getIntAttribute("firstrow"),
                    uidl.getIntAttribute("rows"));
            bodyContainer.add(tBody);
            initialContentReceived = true;
            if (isAttached()) {
                sizeInit();
            }
        }
        hideScrollPositionAnnotation();
        purgeUnregistryBag();
    }

    protected IScrollTableBody createBody() {
        return new IScrollTableBody();
    }

    /**
     * Unregisters Paintables in "trashed" HasWidgets (IScrollTableBodys or
     * IScrollTableRows). This is done lazily as Table must survive from
     * "subtreecaching" logic.
     */
    private void purgeUnregistryBag() {
        for (Iterator iterator = lazyUnregistryBag.iterator(); iterator
                .hasNext();) {
            client.unregisterChildPaintables((HasWidgets) iterator.next());
        }
        lazyUnregistryBag.clear();
    }

    private void updateActionMap(UIDL c) {
        final Iterator it = c.getChildIterator();
        while (it.hasNext()) {
            final UIDL action = (UIDL) it.next();
            final String key = action.getStringAttribute("key");
            final String caption = action.getStringAttribute("caption");
            actionMap.put(key + "_c", caption);
            if (action.hasAttribute("icon")) {
                // TODO need some uri handling ??
                actionMap.put(key + "_i", client.translateToolkitUri(action
                        .getStringAttribute("icon")));
            }
        }

    }

    public String getActionCaption(String actionKey) {
        return (String) actionMap.get(actionKey + "_c");
    }

    public String getActionIcon(String actionKey) {
        return (String) actionMap.get(actionKey + "_i");
    }

    private void updateHeader(String[] strings) {
        if (strings == null) {
            return;
        }

        int visibleCols = strings.length;
        int colIndex = 0;
        if (showRowHeaders) {
            tHead.enableColumn("0", colIndex);
            visibleCols++;
            visibleColOrder = new String[visibleCols];
            visibleColOrder[colIndex] = "0";
            colIndex++;
        } else {
            visibleColOrder = new String[visibleCols];
            tHead.removeCell("0");
        }

        int i;
        for (i = 0; i < strings.length; i++) {
            final String cid = strings[i];
            visibleColOrder[colIndex] = cid;
            tHead.enableColumn(cid, colIndex);
            colIndex++;
        }

        tHead.setVisible(showColHeaders);

    }

    /**
     * @param uidl
     *            which contains row data
     * @param firstRow
     *            first row in data set
     * @param reqRows
     *            amount of rows in data set
     */
    private void updateBody(UIDL uidl, int firstRow, int reqRows) {
        if (uidl == null || reqRows < 1) {
            // container is empty, remove possibly existing rows
            if (firstRow < 0) {
                while (tBody.getLastRendered() > tBody.firstRendered) {
                    tBody.unlinkRow(false);
                }
                tBody.unlinkRow(false);
            }
            return;
        }

        tBody.renderRows(uidl, firstRow, reqRows);

        final int optimalFirstRow = (int) (firstRowInViewPort - pageLength
                * CACHE_RATE);
        boolean cont = true;
        while (cont && tBody.getLastRendered() > optimalFirstRow
                && tBody.getFirstRendered() < optimalFirstRow) {
            // client.console.log("removing row from start");
            cont = tBody.unlinkRow(true);
        }
        final int optimalLastRow = (int) (firstRowInViewPort + pageLength + pageLength
                * CACHE_RATE);
        cont = true;
        while (cont && tBody.getLastRendered() > optimalLastRow) {
            // client.console.log("removing row from the end");
            cont = tBody.unlinkRow(false);
        }
        tBody.fixSpacers();

    }

    /**
     * Gives correct column index for given column key ("cid" in UIDL).
     *
     * @param colKey
     * @return column index of visible columns, -1 if column not visible
     */
    protected int getColIndexByKey(String colKey) {
        // return 0 if asked for rowHeaders
        if ("0".equals(colKey)) {
            return 0;
        }
        for (int i = 0; i < visibleColOrder.length; i++) {
            if (visibleColOrder[i].equals(colKey)) {
                return i;
            }
        }
        return -1;
    }

    protected boolean isCollapsedColumn(String colKey) {
        if (collapsedColumns == null) {
            return false;
        }
        if (collapsedColumns.contains(colKey)) {
            return true;
        }
        return false;
    }

    protected String getColKeyByIndex(int index) {
        return tHead.getHeaderCell(index).getColKey();
    }

    protected void setColWidth(int colIndex, int w) {
        final HeaderCell cell = tHead.getHeaderCell(colIndex);
        cell.setWidth(w);
        tBody.setColWidth(colIndex, w);
    }

    protected int getColWidth(String colKey) {
        return tHead.getHeaderCell(colKey).getWidth();
    }

    private IScrollTableBody.IScrollTableRow getRenderedRowByKey(String key) {
        final Iterator it = tBody.iterator();
        IScrollTableBody.IScrollTableRow r;
        while (it.hasNext()) {
            r = (IScrollTableBody.IScrollTableRow) it.next();
            if (r.getKey().equals(key)) {
                return r;
            }
        }
        return null;
    }

    private void reOrderColumn(String columnKey, int newIndex) {

        final int oldIndex = getColIndexByKey(columnKey);

        // Change header order
        tHead.moveCell(oldIndex, newIndex);

        // Change body order
        tBody.moveCol(oldIndex, newIndex);

        /*
         * Build new columnOrder and update it to server Note that columnOrder
         * also contains collapsed columns so we cannot directly build it from
         * cells vector Loop the old columnOrder and append in order to new
         * array unless on moved columnKey. On new index also put the moved key
         * i == index on columnOrder, j == index on newOrder
         */
        final String oldKeyOnNewIndex = visibleColOrder[newIndex];
        if (showRowHeaders) {
            newIndex--; // columnOrder don't have rowHeader
        }
        // add back hidden rows,
        for (int i = 0; i < columnOrder.length; i++) {
            if (columnOrder[i].equals(oldKeyOnNewIndex)) {
                break; // break loop at target
            }
            if (isCollapsedColumn(columnOrder[i])) {
                newIndex++;
            }
        }
        // finally we can build the new columnOrder for server
        final String[] newOrder = new String[columnOrder.length];
        for (int i = 0, j = 0; j < newOrder.length; i++) {
            if (j == newIndex) {
                newOrder[j] = columnKey;
                j++;
            }
            if (i == columnOrder.length) {
                break;
            }
            if (columnOrder[i].equals(columnKey)) {
                continue;
            }
            newOrder[j] = columnOrder[i];
            j++;
        }
        columnOrder = newOrder;
        // also update visibleColumnOrder
        int i = showRowHeaders ? 1 : 0;
        for (int j = 0; j < newOrder.length; j++) {
            final String cid = newOrder[j];
            if (!isCollapsedColumn(cid)) {
                visibleColOrder[i++] = cid;
            }
        }
        client.updateVariable(paintableId, "columnorder", columnOrder, false);
    }

    @Override
    protected void onAttach() {
        super.onAttach();
        if (initialContentReceived) {
            sizeInit();
        }
    }

    @Override
    protected void onDetach() {
        rowRequestHandler.cancel();
        super.onDetach();
        // ensure that scrollPosElement will be detached
        if (scrollPositionElement != null) {
            final Element parent = DOM.getParent(scrollPositionElement);
            if (parent != null) {
                DOM.removeChild(parent, scrollPositionElement);
            }
        }
    }

    /**
     * Run only once when component is attached and received its initial
     * content. This function : * Syncs headers and bodys "natural widths and
     * saves the values. * Sets proper width and height * Makes deferred request
     * to get some cache rows
     */
    protected void sizeInit() {
        /*
         * We will use browsers table rendering algorithm to find proper column
         * widths. If content and header take less space than available, we will
         * divide extra space relatively to each column which has not width set.
         *
         * Overflow pixels are added to last column.
         */

        Iterator<Widget> headCells = tHead.iterator();
        int i = 0;
        int totalExplicitColumnsWidths = 0;
        int total = 0;

        final int[] widths = new int[tHead.visibleCells.size()];

        tHead.enableBrowserIntelligence();
        // first loop: collect natural widths
        while (headCells.hasNext()) {
            final HeaderCell hCell = (HeaderCell) headCells.next();
            int w = hCell.getWidth();
            if (w > 0) {
                // server has defined column width explicitly
                totalExplicitColumnsWidths += w;
            } else {
                final int hw = hCell.getOffsetWidth();
                final int cw = tBody.getColWidth(i);
                w = (hw > cw ? hw : cw) + IScrollTableBody.CELL_EXTRA_WIDTH;
            }
            widths[i] = w;
            total += w;
            i++;
        }

        tHead.disableBrowserIntelligence();

        int scrollbarWidth = Util.getNativeScrollbarSize();

        // fix "natural" width if width not set
        if (width == null || "".equals(width)) {
            setContentWidth(total);
        }

        int availW = tBody.getAvailableWidth();
        // Hey IE, are you really sure about this?
        availW = tBody.getAvailableWidth() - scrollbarWidth;

        boolean needsReLayout = false;

        if (availW > total || allowMultiStingCells/*fix an issue with the scrollbar appearing*/) {
            // natural size is smaller than available space
            int extraSpace = availW - total;
            int totalWidthR = total - totalExplicitColumnsWidths;
            if (totalWidthR > 0) {
                needsReLayout = true;

                /*
                 * If the table has a relative width and there is enough space
                 * for a scrollbar we reserve this in the last column
                 */
                if (relativeWidth && totalWidthR >= scrollbarWidth) {
                    scrollbarWidthReserved = scrollbarWidth + 1; //
                    int columnindex = tHead.getVisibleCellCount() - 1;
                    widths[columnindex] += scrollbarWidthReserved;
                    HeaderCell headerCell = tHead.getHeaderCell(columnindex);
                    if (headerCell.getWidth() == -1) {
                        totalWidthR += scrollbarWidthReserved;
                    }
                    extraSpace -= scrollbarWidthReserved;
                    scrollbarWidthReservedInColumn = columnindex;
                }

                calculatedWidth = 0;

                // now we will share this sum relatively to those without
                // explicit width
                headCells = tHead.iterator();
                i = 0;
                HeaderCell hCell;
                while (headCells.hasNext()) {
                    hCell = (HeaderCell) headCells.next();
                    if (hCell.getWidth() == -1) {
                        int w = widths[i];
                        final int newSpace;
                        if (availW > total) {
                            newSpace = extraSpace * w / totalWidthR;
                        } else {
                            newSpace = (int) Math.floor((double) extraSpace * (double) w / (double) totalWidthR);
                        }
                        w += newSpace;
                        widths[i] = w;
                        calculatedWidth += w;
                    } else {
                        calculatedWidth += hCell.getWidth();
                    }
                    i++;
                }
            }
        } else {
            // bodys size will be more than available and scrollbar will appear
            calculatedWidth = total;
        }

        // last loop: set possibly modified values or reset if new tBody
        i = 0;
        headCells = tHead.iterator();
        while (headCells.hasNext()) {
            final HeaderCell hCell = (HeaderCell) headCells.next();
            if (isNewBody || hCell.getWidth() == -1) {
                final int w = widths[i];
                setColWidth(i, w);
            }
            i++;
        }

        // fix "natural" height if height not set
        if (height == null || "".equals(height)) {
            int bodyHeight;
            if (!allowMultiStingCells) {
                bodyHeight = tBody.getRowHeight() *
                    (totalRows < pageLength ? ((totalRows < 1) ? 1 : totalRows) : pageLength);
            } else {
                tBody.setContainerHeight();
                bodyHeight = tBody.getContainerHeight();
                if (bodyHeight == 0) {
                    bodyHeight = IScrollTableBody.DEFAULT_ROW_HEIGHT;
                }
            }
            if (total + scrollbarWidth >= availW) {
                bodyHeight = bodyHeight + scrollbarWidth; //fix an issue with a horizontal scrollbar;
            }

            //It should fix an issue with a vertical scrollbar in Chrome
            int h = bodyContainer.getOffsetHeight();
            if (h > bodyHeight) {
                bodyHeight = h;
            }

            bodyContainer.setHeight(bodyHeight + "px");
        }

        if (needsReLayout) {
            tBody.reLayoutComponents();
        }

        isNewBody = false;

        if (firstvisible > 0) {
            // Deferred due some Firefox oddities. IE & Safari could survive
            // without
            DeferredCommand.addCommand(new Command() {
                public void execute() {
                    bodyContainer.setScrollPosition(firstvisible
                            * tBody.getRowHeight());
                    firstRowInViewPort = firstvisible;
                }
            });
        }

        if (enabled) {
            // Do we need cache rows
            if (tBody.getLastRendered() + 1 < firstRowInViewPort + pageLength
                    + CACHE_REACT_RATE * pageLength) {
                if (totalRows - 1 > tBody.getLastRendered()) {
                    // fetch cache rows
                    rowRequestHandler
                            .setReqFirstRow(tBody.getLastRendered() + 1);
                    rowRequestHandler
                            .setReqRows((int) (pageLength * CACHE_RATE));
                    rowRequestHandler.deferRowFetch(1);
                }
            }
        }
        initializedAndAttached = true;
    }

    /**
     * This method has logic which rows needs to be requested from server when
     * user scrolls
     */
    public void onScroll(Widget widget, int scrollLeft, int scrollTop) {
        if (!initializedAndAttached) {
            return;
        }
        if (!enabled) {
            bodyContainer.setScrollPosition(firstRowInViewPort
                    * tBody.getRowHeight());
            return;
        }

        rowRequestHandler.cancel();

        // fix headers horizontal scrolling
        tHead.setHorizontalScrollPosition(scrollLeft);

        firstRowInViewPort = (int) Math.ceil(scrollTop
                / (double) tBody.getRowHeight());
        // ApplicationConnection.getConsole().log(
        // "At scrolltop: " + scrollTop + " At row " + firstRowInViewPort);

        int postLimit = (int) (firstRowInViewPort + pageLength + pageLength
                * CACHE_REACT_RATE);
        if (postLimit > totalRows - 1) {
            postLimit = totalRows - 1;
        }
        int preLimit = (int) (firstRowInViewPort - pageLength
                * CACHE_REACT_RATE);
        if (preLimit < 0) {
            preLimit = 0;
        }
        final int lastRendered = tBody.getLastRendered();
        final int firstRendered = tBody.getFirstRendered();

        if (postLimit <= lastRendered && preLimit >= firstRendered) {
            // remember which firstvisible we requested, in case the server has
            // a differing opinion
            lastRequestedFirstvisible = firstRowInViewPort;
            client.updateVariable(paintableId, "firstvisible",
                    firstRowInViewPort, false);
            return; // scrolled withing "non-react area"
        }

        if (firstRowInViewPort - pageLength * CACHE_RATE > lastRendered
                || firstRowInViewPort + pageLength + pageLength * CACHE_RATE < firstRendered) {
            // need a totally new set
            // ApplicationConnection.getConsole().log(
            // "Table: need a totally new set");
            rowRequestHandler
                    .setReqFirstRow((int) (firstRowInViewPort - pageLength
                            * CACHE_RATE));
            int last = firstRowInViewPort + (int) CACHE_RATE * pageLength
                    + pageLength;
            if (last > totalRows) {
                last = totalRows - 1;
            }
            rowRequestHandler.setReqRows(last
                    - rowRequestHandler.getReqFirstRow() + 1);
            rowRequestHandler.deferRowFetch();
            return;
        }
        if (preLimit < firstRendered) {
            // need some rows to the beginning of the rendered area
            // ApplicationConnection
            // .getConsole()
            // .log(
            // "Table: need some rows to the beginning of the rendered area");
            rowRequestHandler
                    .setReqFirstRow((int) (firstRowInViewPort - pageLength
                            * CACHE_RATE));
            rowRequestHandler.setReqRows(firstRendered
                    - rowRequestHandler.getReqFirstRow());
            rowRequestHandler.deferRowFetch();

            return;
        }
        if (postLimit > lastRendered) {
            // need some rows to the end of the rendered area
            // ApplicationConnection.getConsole().log(
            // "need some rows to the end of the rendered area");
            rowRequestHandler.setReqFirstRow(lastRendered + 1);
            rowRequestHandler.setReqRows((int) ((firstRowInViewPort
                    + pageLength + pageLength * CACHE_RATE) - lastRendered));
            rowRequestHandler.deferRowFetch();
        }

    }

    private void announceScrollPosition() {
        if (scrollPositionElement == null) {
            scrollPositionElement = DOM.createDiv();
            DOM.setElementProperty(scrollPositionElement, "className",
                    "i-table-scrollposition");
            DOM.appendChild(getElement(), scrollPositionElement);
        }

        DOM.setStyleAttribute(scrollPositionElement, "position", "absolute");
        DOM.setStyleAttribute(scrollPositionElement, "marginLeft", (DOM
                .getElementPropertyInt(getElement(), "offsetWidth") / 2 - 80)
                + "px");
        DOM.setStyleAttribute(scrollPositionElement, "marginTop", -(DOM
                .getElementPropertyInt(getElement(), "offsetHeight") - 2)
                + "px");

        // indexes go from 1-totalRows, as rowheaders in index-mode indicate
        int last = (firstRowInViewPort + (bodyContainer.getOffsetHeight() / tBody
                .getRowHeight()));
        if (last > totalRows) {
            last = totalRows;
        }
        DOM.setInnerHTML(scrollPositionElement, "<span>"
                + (firstRowInViewPort + 1) + " &ndash; " + last + "..."
                + "</span>");
        DOM.setStyleAttribute(scrollPositionElement, "display", "block");
    }

    private void hideScrollPositionAnnotation() {
        if (scrollPositionElement != null) {
            DOM.setStyleAttribute(scrollPositionElement, "display", "none");
        }
    }

    protected class RowRequestHandler extends Timer {

        private int reqFirstRow = 0;
        private int reqRows = 0;

        public void deferRowFetch() {
            deferRowFetch(250);
        }

        public void deferRowFetch(int msec) {
            if (reqRows > 0 && reqFirstRow < totalRows) {
                schedule(msec);

                // tell scroll position to user if currently "visible" rows are
                // not rendered
                if ((firstRowInViewPort + pageLength > tBody.getLastRendered())
                        || (firstRowInViewPort < tBody.getFirstRendered())) {
                    announceScrollPosition();
                } else {
                    hideScrollPositionAnnotation();
                }
            }
        }

        public void setReqFirstRow(int reqFirstRow) {
            if (reqFirstRow < 0) {
                reqFirstRow = 0;
            } else if (reqFirstRow >= totalRows) {
                reqFirstRow = totalRows - 1;
            }
            this.reqFirstRow = reqFirstRow;
        }

        public void setReqRows(int reqRows) {
            this.reqRows = reqRows;
        }

        @Override
        public void run() {
            if (client.hasActiveRequest()) {
                // if client connection is busy, don't bother loading it more
                schedule(250);
                ApplicationConnection.getConsole().log(
                        "Table: AC is busy, deferring cache row fetch..");

            } else {
                ApplicationConnection.getConsole().log(
                        "Getting " + reqRows + " rows from " + reqFirstRow);

                int firstToBeRendered = tBody.firstRendered;
                if (reqFirstRow < firstToBeRendered) {
                    firstToBeRendered = reqFirstRow;
                } else if (firstRowInViewPort - (int) (CACHE_RATE * pageLength) > firstToBeRendered) {
                    firstToBeRendered = firstRowInViewPort
                            - (int) (CACHE_RATE * pageLength);
                    if (firstToBeRendered < 0) {
                        firstToBeRendered = 0;
                    }
                }

                int lastToBeRendered = tBody.lastRendered;

                if (reqFirstRow + reqRows - 1 > lastToBeRendered) {
                    lastToBeRendered = reqFirstRow + reqRows - 1;
                } else if (firstRowInViewPort + pageLength + pageLength
                        * CACHE_RATE < lastToBeRendered) {
                    lastToBeRendered = (firstRowInViewPort + pageLength + (int) (pageLength * CACHE_RATE));
                    if (lastToBeRendered >= totalRows) {
                        lastToBeRendered = totalRows - 1;
                    }
                }

                client.updateVariable(paintableId, "firstToBeRendered",
                        firstToBeRendered, false);

                client.updateVariable(paintableId, "lastToBeRendered",
                        lastToBeRendered, false);
                // remember which firstvisible we requested, in case the server
                // has
                // a differing opinion
                lastRequestedFirstvisible = firstRowInViewPort;
                client.updateVariable(paintableId, "firstvisible",
                        firstRowInViewPort, false);
                client.updateVariable(paintableId, "reqfirstrow", reqFirstRow,
                        false);
                client.updateVariable(paintableId, "reqrows", reqRows, true);

            }
        }

        public int getReqFirstRow() {
            return reqFirstRow;
        }

        public int getReqRows() {
            return reqRows;
        }

        /**
         * Sends request to refresh content at this position.
         */
        public void refreshContent() {
            int first = (int) (firstRowInViewPort - pageLength * CACHE_RATE);
            int reqRows = (int) (2 * pageLength * CACHE_RATE + pageLength);
            if (first < 0) {
                reqRows = reqRows + first;
                first = 0;
            }
            setReqFirstRow(first);
            setReqRows(reqRows);
            run();
        }
    }

    public class HeaderCell extends Widget {

        private static final int DRAG_WIDGET_WIDTH = 4;

        private static final int MINIMUM_COL_WIDTH = 20;

        Element td = DOM.createTD();

        Element captionContainer = DOM.createDiv();

        Element colResizeWidget = DOM.createDiv();

        Element floatingCopyOfHeaderCell;

        private boolean sortable = false;
        private final String cid;
        private boolean dragging;

        private int dragStartX;
        private int colIndex;
        private int originalWidth;

        private boolean isResizing;

        private int headerX;

        private boolean moved;

        private int closestSlot;

        private int width = -1;

        private char align = ALIGN_LEFT;

        public void setSortable(boolean b) {
            sortable = b;
        }

        public HeaderCell(String colId, String headerText) {
            cid = colId;

            DOM.setElementProperty(colResizeWidget, "className", CLASSNAME
                    + "-resizer");
            DOM.setStyleAttribute(colResizeWidget, "width", DRAG_WIDGET_WIDTH
                    + "px");
            DOM.sinkEvents(colResizeWidget, Event.MOUSEEVENTS);

            setText(headerText);

            DOM.appendChild(td, colResizeWidget);

            DOM.setElementProperty(captionContainer, "className", CLASSNAME
                    + "-caption-container");

            // ensure no clipping initially (problem on column additions)
            DOM.setStyleAttribute(captionContainer, "overflow", "visible");

            DOM.sinkEvents(captionContainer, Event.MOUSEEVENTS);

            DOM.appendChild(td, captionContainer);

            DOM.sinkEvents(td, Event.MOUSEEVENTS);

            setElement(td);
        }

        public void setWidth(int w) {
            if (width == -1) {
                // go to default mode, clip content if necessary
                DOM.setStyleAttribute(captionContainer, "overflow", "");
            }
            width = w;
            if (w == -1) {
                DOM.setStyleAttribute(captionContainer, "width", "");
                setWidth("");
            } else {
                DOM.setStyleAttribute(captionContainer, "width", (w
                        - DRAG_WIDGET_WIDTH - 4)
                        + "px");
                setWidth(w + "px");
            }
        }

        public int getWidth() {
            return width;
        }

        public void setText(String headerText) {
            DOM.setInnerHTML(captionContainer, headerText);
        }

        public String getColKey() {
            return cid;
        }

        private void setSorted(boolean sorted) {
            if (sorted) {
                if (sortAscending) {
                    this.setStyleName(CLASSNAME + "-header-cell-asc");
                } else {
                    this.setStyleName(CLASSNAME + "-header-cell-desc");
                }
            } else {
                this.setStyleName(CLASSNAME + "-header-cell");
            }
        }

        /**
         * Handle column reordering.
         */
        @Override
        public void onBrowserEvent(Event event) {
            if (enabled && event != null) {
                if (isResizing || event.getTarget() == colResizeWidget) {
                    onResizeEvent(event);
                } else {
                    handleCaptionEvent(event);
                }
            }
        }

        private void createFloatingCopy() {
            floatingCopyOfHeaderCell = DOM.createDiv();
            DOM.setInnerHTML(floatingCopyOfHeaderCell, DOM.getInnerHTML(td));
            floatingCopyOfHeaderCell = DOM
                    .getChild(floatingCopyOfHeaderCell, 1);
            DOM.setElementProperty(floatingCopyOfHeaderCell, "className",
                    CLASSNAME + "-header-drag");
            updateFloatingCopysPosition(DOM.getAbsoluteLeft(td), DOM
                    .getAbsoluteTop(td));
            DOM.appendChild(RootPanel.get().getElement(),
                    floatingCopyOfHeaderCell);
        }

        private void updateFloatingCopysPosition(int x, int y) {
            x -= DOM.getElementPropertyInt(floatingCopyOfHeaderCell,
                    "offsetWidth") / 2;
            DOM.setStyleAttribute(floatingCopyOfHeaderCell, "left", x + "px");
            if (y > 0) {
                DOM.setStyleAttribute(floatingCopyOfHeaderCell, "top", (y + 7)
                        + "px");
            }
        }

        private void hideFloatingCopy() {
            DOM.removeChild(RootPanel.get().getElement(),
                    floatingCopyOfHeaderCell);
            floatingCopyOfHeaderCell = null;
        }

        protected void handleCaptionEvent(Event event) {
            switch (DOM.eventGetType(event)) {
            case Event.ONMOUSEDOWN:
                ApplicationConnection.getConsole().log(
                        "HeaderCaption: mouse down");
                if (columnReordering) {
                    dragging = true;
                    moved = false;
                    colIndex = getColIndexByKey(cid);
                    DOM.setCapture(getElement());
                    headerX = tHead.getAbsoluteLeft();
                    ApplicationConnection
                            .getConsole()
                            .log(
                                    "HeaderCaption: Caption set to capture mouse events");
                    DOM.eventPreventDefault(event); // prevent selecting text
                }
                break;
            case Event.ONMOUSEUP:
                ApplicationConnection.getConsole()
                        .log("HeaderCaption: mouseUP");
                if (columnReordering) {
                    dragging = false;
                    DOM.releaseCapture(getElement());
                    ApplicationConnection.getConsole().log(
                            "HeaderCaption: Stopped column reordering");
                    if (moved) {
                        hideFloatingCopy();
                        tHead.removeSlotFocus();
                        if (closestSlot != colIndex
                                && closestSlot != (colIndex + 1)) {
                            if (closestSlot > colIndex) {
                                reOrderColumn(cid, closestSlot - 1);
                            } else {
                                reOrderColumn(cid, closestSlot);
                            }
                        }
                    }
                }

                if (!moved) {
                    // mouse event was a click to header -> sort column
                    if (sortable) {
                        if (sortColumn.equals(cid)) {
                            // just toggle order
                            client.updateVariable(paintableId, "sortascending",
                                    !sortAscending, false);
                        } else {
                            // set table scrolled by this column
                            client.updateVariable(paintableId, "sortcolumn",
                                    cid, false);
                        }
                        // get also cache columns at the same request
                        bodyContainer.setScrollPosition(0);
                        firstvisible = 0;
                        rowRequestHandler.setReqFirstRow(0);
                        rowRequestHandler.setReqRows((int) (2 * pageLength
                                * CACHE_RATE + pageLength));
                        rowRequestHandler.deferRowFetch();
                    }
                    break;
                }
                break;
            case Event.ONMOUSEMOVE:
                if (dragging) {
                    ApplicationConnection.getConsole().log(
                            "HeaderCaption: Dragging column, optimal index...");
                    if (!moved) {
                        createFloatingCopy();
                        moved = true;
                    }
                    final int x = DOM.eventGetClientX(event)
                            + DOM.getElementPropertyInt(tHead.hTableWrapper,
                                    "scrollLeft");
                    int slotX = headerX;
                    closestSlot = colIndex;
                    int closestDistance = -1;
                    int start = 0;
                    if (showRowHeaders) {
                        start++;
                    }
                    final int visibleCellCount = tHead.getVisibleCellCount();
                    for (int i = start; i <= visibleCellCount; i++) {
                        if (i > 0) {
                            final String colKey = getColKeyByIndex(i - 1);
                            slotX += getColWidth(colKey);
                        }
                        final int dist = Math.abs(x - slotX);
                        if (closestDistance == -1 || dist < closestDistance) {
                            closestDistance = dist;
                            closestSlot = i;
                        }
                    }
                    tHead.focusSlot(closestSlot);

                    updateFloatingCopysPosition(DOM.eventGetClientX(event), -1);
                    ApplicationConnection.getConsole().log("" + closestSlot);
                }
                break;
            default:
                break;
            }
        }

        private void onResizeEvent(Event event) {
            switch (DOM.eventGetType(event)) {
            case Event.ONMOUSEDOWN:
                isResizing = true;
                DOM.setCapture(getElement());
                dragStartX = DOM.eventGetClientX(event);
                colIndex = getColIndexByKey(cid);
                originalWidth = getWidth();
                DOM.eventPreventDefault(event);
                break;
            case Event.ONMOUSEUP:
                isResizing = false;
                DOM.releaseCapture(getElement());
                tBody.reLayoutComponents();
                break;
            case Event.ONMOUSEMOVE:
                if (isResizing) {
                    final int deltaX = DOM.eventGetClientX(event) - dragStartX;
                    if (deltaX == 0) {
                        return;
                    }

                    int newWidth = originalWidth + deltaX;
                    if (newWidth < MINIMUM_COL_WIDTH) {
                        newWidth = MINIMUM_COL_WIDTH;
                    }
                    updateCalculatedWidth(colIndex, newWidth);
                    setColWidth(colIndex, newWidth);
                }
                break;
            default:
                break;
            }
        }

        private void updateCalculatedWidth(int colIndex, int newColumnWidth) {
            if (calculatedWidth > -1) {
                int newWidth = 0;
                for (int i = 0; i < tHead.getVisibleCellCount(); i++) {
                    if (i == colIndex) {
                        newWidth += newColumnWidth;
                    } else {
                        HeaderCell cell = (HeaderCell) tHead.getVisibleCells().get(i);
                        newWidth += cell.getWidth();
                    }
                }
                calculatedWidth = newWidth;
            }
        }

        public String getCaption() {
            return DOM.getInnerText(captionContainer);
        }

        public boolean isEnabled() {
            return getParent() != null;
        }

        public void setAlign(char c) {
            if (align != c) {
                switch (c) {
                case ALIGN_CENTER:
                    DOM.setStyleAttribute(captionContainer, "textAlign",
                            "center");
                    break;
                case ALIGN_RIGHT:
                    DOM.setStyleAttribute(captionContainer, "textAlign",
                            "right");
                    break;
                default:
                    DOM.setStyleAttribute(captionContainer, "textAlign", "");
                    break;
                }
            }
            align = c;
        }

        public char getAlign() {
            return align;
        }

    }

    /**
     * HeaderCell that is header cell for row headers.
     *
     * Reordering disabled and clicking on it resets sorting.
     */
    public class RowHeadersHeaderCell extends HeaderCell {

        RowHeadersHeaderCell() {
            super("0", "");
        }

        @Override
        protected void handleCaptionEvent(Event event) {
            // NOP: RowHeaders cannot be reordered
            // TODO It'd be nice to reset sorting here
        }
    }

    public class TableHead extends Panel implements ActionOwner {

        private static final int WRAPPER_WIDTH = 9000;

        Vector<Widget> visibleCells = new Vector<Widget>();

        HashMap<String, HeaderCell> availableCells = new HashMap<String, HeaderCell>();

        Element div = DOM.createDiv();
        Element hTableWrapper = DOM.createDiv();
        Element hTableContainer = DOM.createDiv();
        Element table = DOM.createTable();
        Element headerTableBody = DOM.createTBody();
        Element tr = DOM.createTR();

        private final Element columnSelector = DOM.createDiv();

        private int focusedSlot = -1;

        public TableHead() {
            DOM.setStyleAttribute(hTableWrapper, "overflow", "hidden");
            DOM.setElementProperty(hTableWrapper, "className", CLASSNAME
                    + "-header");

            // TODO move styles to CSS
            DOM.setElementProperty(columnSelector, "className", CLASSNAME
                    + "-column-selector");
            DOM.setStyleAttribute(columnSelector, "display", "none");

            DOM.setElementProperty(hTableContainer, "className", CLASSNAME
                    + "-header-container");

            DOM.appendChild(table, headerTableBody);
            DOM.appendChild(headerTableBody, tr);
            DOM.appendChild(hTableContainer, table);
            DOM.appendChild(hTableWrapper, hTableContainer);
            DOM.appendChild(div, hTableWrapper);
            DOM.appendChild(div, columnSelector);
            setElement(div);

            setStyleName(CLASSNAME + "-header-wrap");

            DOM.sinkEvents(columnSelector, Event.ONCLICK);

            availableCells.put("0", new RowHeadersHeaderCell());
        }

        @Override
        public void clear() {
            for (String cid : availableCells.keySet()) {
                removeCell(cid);
            }
            availableCells.clear();
            availableCells.put("0", new RowHeadersHeaderCell());
        }

        public void updateCellsFromUIDL(UIDL uidl) {
            Iterator it = uidl.getChildIterator();
            HashSet<String> updated = new HashSet<String>();
            updated.add("0");
            while (it.hasNext()) {
                final UIDL col = (UIDL) it.next();
                final String cid = col.getStringAttribute("cid");
                updated.add(cid);

                String caption = buildCaptionHtmlSnippet(col);
                HeaderCell c = getHeaderCell(cid);
                if (c == null) {
                    c = new HeaderCell(cid, caption);
                    availableCells.put(cid, c);
                    if (initializedAndAttached) {
                        // we will need a column width recalculation
                        initializedAndAttached = false;
                        initialContentReceived = false;
                        isNewBody = true;
                    }
                } else {
                    c.setText(caption);
                }

                if (col.hasAttribute("sortable")) {
                    c.setSortable(true);
                    if (cid.equals(sortColumn)) {
                        c.setSorted(true);
                    } else {
                        c.setSorted(false);
                    }
                }
                if (col.hasAttribute("align")) {
                    c.setAlign(col.getStringAttribute("align").charAt(0));
                }
                if (col.hasAttribute("width")) {
                    final String width = col.getStringAttribute("width");
                    c.setWidth(Integer.parseInt(width));
                } else if (recalcWidths) {
                    c.setWidth(-1);
                }
            }
            // check for orphaned header cells
            for (String cid : availableCells.keySet()) {
                if (!updated.contains(cid)) {
                    removeCell(cid);
                    it.remove();
                }
            }

        }

        public void enableColumn(String cid, int index) {
            final HeaderCell c = getHeaderCell(cid);
            if (!c.isEnabled() || getHeaderCell(index) != c) {
                setHeaderCell(index, c);
                if (c.getWidth() == -1) {
                    if (initializedAndAttached) {
                        // column is not drawn before,
                        // we will need a column width recalculation
                        initializedAndAttached = false;
                        initialContentReceived = false;
                        isNewBody = true;
                    }
                }
            }
        }

        public Vector<Widget> getVisibleCells() {
            return visibleCells;
        }

        public int getVisibleCellCount() {
            return visibleCells.size();
        }

        public void setHorizontalScrollPosition(int scrollLeft) {
            DOM.setElementPropertyInt(hTableWrapper, "scrollLeft", scrollLeft);
        }

        public void setColumnCollapsingAllowed(boolean cc) {
            if (cc) {
                DOM.setStyleAttribute(columnSelector, "display", "block");
            } else {
                DOM.setStyleAttribute(columnSelector, "display", "none");
            }
        }

        public void disableBrowserIntelligence() {
            DOM.setStyleAttribute(hTableContainer, "width", WRAPPER_WIDTH
                    + "px");
        }

        public void enableBrowserIntelligence() {
            DOM.setStyleAttribute(hTableContainer, "width", "");
        }

        public void setHeaderCell(int index, HeaderCell cell) {
            if (cell.isEnabled()) {
                // we're moving the cell
                DOM.removeChild(tr, cell.getElement());
                orphan(cell);
            }
            if (index < visibleCells.size()) {
                // insert to right slot
                DOM.insertChild(tr, cell.getElement(), index);
                adopt(cell);
                visibleCells.insertElementAt(cell, index);

            } else if (index == visibleCells.size()) {
                // simply append
                DOM.appendChild(tr, cell.getElement());
                adopt(cell);
                visibleCells.add(cell);
            } else {
                throw new RuntimeException(
                        "Header cells must be appended in order");
            }
        }

        public HeaderCell getHeaderCell(int index) {
            if (index < visibleCells.size()) {
                return (HeaderCell) visibleCells.get(index);
            } else {
                return null;
            }
        }

        /**
         * Get's HeaderCell by it's column Key.
         *
         * Note that this returns HeaderCell even if it is currently collapsed.
         *
         * @param cid
         *            Column key of accessed HeaderCell
         * @return HeaderCell
         */
        public HeaderCell getHeaderCell(String cid) {
            return availableCells.get(cid);
        }

        public void moveCell(int oldIndex, int newIndex) {
            final HeaderCell hCell = getHeaderCell(oldIndex);
            final Element cell = hCell.getElement();

            visibleCells.remove(oldIndex);
            DOM.removeChild(tr, cell);

            DOM.insertChild(tr, cell, newIndex);
            visibleCells.insertElementAt(hCell, newIndex);
        }

        public Iterator<Widget> iterator() {
            return visibleCells.iterator();
        }

        @Override
        public boolean remove(Widget w) {
            if (visibleCells.contains(w)) {
                visibleCells.remove(w);
                orphan(w);
                DOM.removeChild(DOM.getParent(w.getElement()), w.getElement());
                return true;
            }
            return false;
        }

        public void removeCell(String colKey) {
            final HeaderCell c = getHeaderCell(colKey);
            remove(c);
        }

        private void focusSlot(int index) {
            removeSlotFocus();
            if (index > 0) {
                DOM.setElementProperty(DOM.getFirstChild(DOM.getChild(tr,
                        index - 1)), "className", CLASSNAME + "-resizer "
                        + CLASSNAME + "-focus-slot-right");
            } else {
                DOM.setElementProperty(DOM.getFirstChild(DOM
                        .getChild(tr, index)), "className", CLASSNAME
                        + "-resizer " + CLASSNAME + "-focus-slot-left");
            }
            focusedSlot = index;
        }

        private void removeSlotFocus() {
            if (focusedSlot < 0) {
                return;
            }
            if (focusedSlot == 0) {
                DOM.setElementProperty(DOM.getFirstChild(DOM.getChild(tr,
                        focusedSlot)), "className", CLASSNAME + "-resizer");
            } else if (focusedSlot > 0) {
                DOM.setElementProperty(DOM.getFirstChild(DOM.getChild(tr,
                        focusedSlot - 1)), "className", CLASSNAME + "-resizer");
            }
            focusedSlot = -1;
        }

        @Override
        public void onBrowserEvent(Event event) {
            if (enabled) {
                if (event.getTarget() == columnSelector) {
                    final int left = DOM.getAbsoluteLeft(columnSelector);
                    final int top = DOM.getAbsoluteTop(columnSelector)
                            + DOM.getElementPropertyInt(columnSelector,
                                    "offsetHeight");
                    client.getContextMenu().showAt(this, left, top);
                }
            }
        }

        class VisibleColumnAction extends Action {

            String colKey;
            private boolean collapsed;

            public VisibleColumnAction(String colKey) {
                super(IScrollTable.TableHead.this);
                this.colKey = colKey;
                caption = tHead.getHeaderCell(colKey).getCaption();
            }

            @Override
            public void execute() {
                client.getContextMenu().hide();
                // toggle selected column
                if (collapsedColumns.contains(colKey)) {
                    collapsedColumns.remove(colKey);
                } else {
                    tHead.removeCell(colKey);
                    collapsedColumns.add(colKey);
                }

                // update variable to server
                client.updateVariable(paintableId, "collapsedcolumns",
                        collapsedColumns.toArray(), false);
                // let rowRequestHandler determine proper rows
                rowRequestHandler.refreshContent();
            }

            public void setCollapsed(boolean b) {
                collapsed = b;
            }

            /**
             * Override default method to distinguish on/off columns
             */
            @Override
            public String getHTML() {
                final StringBuffer buf = new StringBuffer();
                if (collapsed) {
                    buf.append("<span class=\"i-off\">");
                } else {
                    buf.append("<span class=\"i-on\">");
                }
                buf.append(super.getHTML());
                buf.append("</span>");

                return buf.toString();
            }

        }

        /*
         * Returns columns as Action array for column select popup
         */
        public Action[] getActions() {
            Object[] cols;
            if (columnReordering) {
                cols = columnOrder;
            } else {
                // if columnReordering is disabled, we need different way to get
                // all available columns
                cols = visibleColOrder;
                cols = new Object[visibleColOrder.length
                        + collapsedColumns.size()];
                int i;
                for (i = 0; i < visibleColOrder.length; i++) {
                    cols[i] = visibleColOrder[i];
                }
                for (final Iterator it = collapsedColumns.iterator(); it
                        .hasNext();) {
                    cols[i++] = it.next();
                }
            }
            final Action[] actions = new Action[cols.length];

            for (int i = 0; i < cols.length; i++) {
                final String cid = (String) cols[i];
                final HeaderCell c = getHeaderCell(cid);
                final VisibleColumnAction a = new VisibleColumnAction(c
                        .getColKey());
                a.setCaption(c.getCaption());
                if (!c.isEnabled()) {
                    a.setCollapsed(true);
                }
                actions[i] = a;
            }
            return actions;
        }

        public ApplicationConnection getClient() {
            return client;
        }

        public String getPaintableId() {
            return paintableId;
        }

        /**
         * Returns column alignments for visible columns
         */
        public char[] getColumnAlignments() {
            final Iterator it = visibleCells.iterator();
            final char[] aligns = new char[visibleCells.size()];
            int colIndex = 0;
            while (it.hasNext()) {
                aligns[colIndex++] = ((HeaderCell) it.next()).getAlign();
            }
            return aligns;
        }

    }

    /**
     * This Panel can only contain IScrollTableRow type of widgets. This
     * "simulates" very large table, keeping spacers which take room of
     * unrendered rows.
     *
     */
    public class IScrollTableBody extends Panel {

        public static final int CELL_EXTRA_WIDTH = 20;

        public static final int DEFAULT_ROW_HEIGHT = 24;

        /**
         * Amount of padding inside one table cell (this is reduced from the
         * "cellContent" element's width). You may override this in your own
         * widgetset.
         */
        public static final int CELL_CONTENT_PADDING = 8;

        private int rowHeight = -1;

        protected final List renderedRows = new Vector();

        protected boolean initDone = false;

        Element preSpacer = DOM.createDiv();
        Element postSpacer = DOM.createDiv();

        protected Element container = DOM.createDiv();

        protected Element tBody = DOM.createTBody();
        protected Element table = DOM.createTable();
//        protected Element colGroup = DOM.createColGroup();

//        protected Element[] cols = null;
//        protected Element hiddenRow = DOM.createTR();

        protected int firstRendered;

        protected int lastRendered;

        protected char[] aligns;

        protected IScrollTableBody() {
            constructDOM();
            setElement(container);
        }

        private void constructDOM() {
            DOM.setElementProperty(table, "className", CLASSNAME + "-table");
//            DOM.setElementProperty(hiddenRow, "className", CLASSNAME + "-hidden-row");
            DOM.setElementProperty(preSpacer, "className", CLASSNAME
                    + "-row-spacer");
            DOM.setElementProperty(postSpacer, "className", CLASSNAME
                    + "-row-spacer");

//            DOM.appendChild(tBody, hiddenRow);
//            DOM.appendChild(table, colGroup);
            DOM.appendChild(table, tBody);
            DOM.appendChild(container, preSpacer);
            DOM.appendChild(container, table);
            DOM.appendChild(container, postSpacer);

        }

        public int getAvailableWidth() {
            return DOM.getElementPropertyInt(preSpacer, "offsetWidth");
        }

        public void renderInitialRows(UIDL rowData, int firstIndex, int rows) {
            firstRendered = firstIndex;
            lastRendered = firstIndex + rows - 1;
            final Iterator it = rowData.getChildIterator();
            aligns = tHead.getColumnAlignments();
            while (it.hasNext()) {
                final IScrollTableRow row = new IScrollTableRow((UIDL) it.next(),
                        aligns);
                addRow(row);
            }
            if (isAttached()) {
                fixSpacers();
            }
        }

/*
        protected void initCols() {
            if (colGroup.hasChildNodes()) {
                Tools.removeChildren(colGroup);
            }

            if (hiddenRow.hasChildNodes()) {
                Tools.removeChildren(hiddenRow);
            }

            int cellsCount = tHead.getVisibleCellCount();
            if (showRowHeaders) {
                cellsCount++;
            }

            cols = new Element[cellsCount];

            for (int i = 0; i < cellsCount; i++ ) {
                cols[i] = DOM.createCol();
                colGroup.appendChild(cols[i]);
                final Element td = DOM.createTD();
                DOM.setInnerHTML(td, "&nbsp;");
                hiddenRow.appendChild(td);
            }
        }
*/

        public void renderRows(UIDL rowData, int firstIndex, int rows) {
            // FIXME REVIEW
            aligns = tHead.getColumnAlignments();
            final Iterator it = rowData.getChildIterator();
            if (firstIndex == lastRendered + 1) {
                while (it.hasNext()) {
                    final IScrollTableRow row = createRow((UIDL) it.next());
                    addRow(row);
                    lastRendered++;
                }
                fixSpacers();
            } else if (firstIndex + rows == firstRendered) {
                final IScrollTableRow[] rowArray = new IScrollTableRow[rows];
                int i = rows;
                while (it.hasNext()) {
                    i--;
                    rowArray[i] = createRow((UIDL) it.next());
                }
                for (i = 0; i < rows; i++) {
                    addRowBeforeFirstRendered(rowArray[i]);
                    firstRendered--;
                }
            } else {
                // completely new set of rows
                while (lastRendered + 1 > firstRendered) {
                    unlinkRow(false);
                }
                final IScrollTableRow row = createRow((UIDL) it.next());
                firstRendered = firstIndex;
                lastRendered = firstIndex - 1;
                addRow(row);
                lastRendered++;
                setContainerHeight();
                fixSpacers();
                while (it.hasNext()) {
                    addRow(createRow((UIDL) it.next()));
                    lastRendered++;
                }
                fixSpacers();
            }
            // this may be a new set of rows due content change,
            // ensure we have proper cache rows
            int reactFirstRow = (int) (firstRowInViewPort - pageLength
                    * CACHE_REACT_RATE);
            int reactLastRow = (int) (firstRowInViewPort + pageLength + pageLength
                    * CACHE_REACT_RATE);
            if (reactFirstRow < 0) {
                reactFirstRow = 0;
            }
            if (reactLastRow > totalRows) {
                reactLastRow = totalRows - 1;
            }
            if (lastRendered < reactLastRow) {
                // get some cache rows below visible area
                rowRequestHandler.setReqFirstRow(lastRendered + 1);
                rowRequestHandler.setReqRows(reactLastRow - lastRendered - 1);
                rowRequestHandler.deferRowFetch(1);
            } else if (IScrollTable.this.tBody.getFirstRendered() > reactFirstRow) {
                /*
                 * Branch for fetching cache above visible area.
                 *
                 * If cache needed for both before and after visible area, this
                 * will be rendered after-cache is reveived and rendered. So in
                 * some rare situations table may take two cache visits to
                 * server.
                 */
                rowRequestHandler.setReqFirstRow(reactFirstRow);
                rowRequestHandler.setReqRows(firstRendered - reactFirstRow);
                rowRequestHandler.deferRowFetch(1);
            }
        }

        /**
         * This method is used to instantiate new rows for this table. It
         * automatically sets correct widths to rows cells and assigns correct
         * client reference for child widgets.
         *
         * This method can be called only after table has been initialized
         *
         * @param uidl
         */
        protected IScrollTableRow createRow(UIDL uidl) {
            final IScrollTableRow row = new IScrollTableRow(uidl, aligns);
            final int cells = DOM.getChildCount(row.getElement());
            for (int i = 0; i < cells; i++) {
                final Element cell = DOM.getChild(row.getElement(), i);
                final int w = IScrollTable.this
                        .getColWidth(getColKeyByIndex(i));
                DOM.setStyleAttribute(DOM.getFirstChild(cell), "width",
                        (w - CELL_CONTENT_PADDING) + "px");
                DOM.setStyleAttribute(cell, "width", w + "px");
            }
            return row;
        }

        protected void addRowBeforeFirstRendered(IScrollTableRow row) {
            IScrollTableRow first = null;
            if (renderedRows.size() > 0) {
                first = (IScrollTableRow) renderedRows.get(0);
            }
            if (first != null && first.getStyleName().indexOf("-odd") == -1) {
                applyAlternatingRowColor(row, "-row-odd");
            } else {
                applyAlternatingRowColor(row, "-row");
            }
            if (row.isSelected()) {
                row.addStyleName("i-selected");
            }
            DOM.insertChild(tBody, row.getElement(), 0);
            adopt(row);
            renderedRows.add(0, row);
        }

        protected void addRow(IScrollTableRow row) {
            IScrollTableRow last = null;
            if (renderedRows.size() > 0) {
                last = (IScrollTableRow) renderedRows
                        .get(renderedRows.size() - 1);
            }
            if (last != null && last.getStyleName().indexOf("-odd") == -1) {
                applyAlternatingRowColor(row, "-row-odd");
            } else {
                applyAlternatingRowColor(row, "-row");
            }
            if (row.isSelected()) {
                row.addStyleName("i-selected");
            }
            DOM.appendChild(tBody, row.getElement());
            adopt(row);
            renderedRows.add(row);
        }

        protected void applyAlternatingRowColor(IScrollTableRow row, String style) {
            row.addStyleName(CLASSNAME + style);
        }

        public Iterator iterator() {
            return renderedRows.iterator();
        }

        /**
         * @return false if couldn't remove row
         */
        public boolean unlinkRow(boolean fromBeginning) {
            if (lastRendered - firstRendered < 0) {
                return false;
            }
            int index;
            if (fromBeginning) {
                index = 0;
                firstRendered++;
            } else {
                index = renderedRows.size() - 1;
                lastRendered--;
            }
            final IScrollTableRow toBeRemoved = (IScrollTableRow) renderedRows
                    .get(index);
            lazyUnregistryBag.add(toBeRemoved);
            DOM.removeChild(tBody, toBeRemoved.getElement());
            orphan(toBeRemoved);
            renderedRows.remove(index);
            fixSpacers();
            return true;
        }

        @Override
        public boolean remove(Widget w) {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void onAttach() {
            super.onAttach();
            setContainerHeight();
        }

        private int containerHeight = -1;
        /**
         * Fix container blocks height according to totalRows to avoid
         * "bouncing" when scrolling
         */
        public void setContainerHeight() {
            fixSpacers();
            if (!allowMultiStingCells) {
                containerHeight = totalRows * getRowHeight();
            } else {
                containerHeight = 0;
                for (final Object o : renderedRows) {
                    final IScrollTableRow row = (IScrollTableRow) o;
                    containerHeight += row.getHeight();
                }
            }
            DOM.setStyleAttribute(container, "height", containerHeight + "px");
        }

        public int getContainerHeight() {
            if (containerHeight == -1) {
                setContainerHeight();
            }
            return containerHeight;
        }

        protected void fixSpacers() {
            int prepx = getRowHeight() * firstRendered;
            if (prepx < 0) {
                prepx = 0;
            }
            DOM.setStyleAttribute(preSpacer, "height", prepx + "px");
            int postpx = getRowHeight() * (totalRows - 1 - lastRendered);
            if (postpx < 0) {
                postpx = 0;
            }
            DOM.setStyleAttribute(postSpacer, "height", postpx + "px");
        }

        public int getRowHeight() {
            if (initDone) {
                return rowHeight;
            } else {
                if (DOM.getChildCount(tBody) > 0) {
                    IScrollTableRow row = (IScrollTableRow) renderedRows.get(0);
                    rowHeight = row.getHeight();
                } else {
                    return DEFAULT_ROW_HEIGHT;
                }
                initDone = true;
                return rowHeight;
            }
        }

        public int getColWidth(int i) {
            if (initDone) {
                final Element e = DOM.getChild(DOM.getChild(tBody, 0), i);
                return DOM.getElementPropertyInt(e, "offsetWidth");
            } else {
                return 0;
            }
        }

        public void setColWidth(int colIndex, int w) {
            final int rows = DOM.getChildCount(tBody);
            for (int i = 0; i < rows; i++) {
                final Element cell = DOM.getChild(DOM.getChild(tBody, i),
                        colIndex);
                DOM.setStyleAttribute(DOM.getFirstChild(cell), "width",
                        (w - CELL_CONTENT_PADDING) + "px");
                DOM.setStyleAttribute(cell, "width", w + "px");
            }
        }

        public void reLayoutComponents() {
            for (Widget w : this) {
                IScrollTableRow r = (IScrollTableRow) w;
                for (Widget widget : r) {
                    client.handleComponentRelativeSize(widget);
                }
            }
        }

        public int getLastRendered() {
            return lastRendered;
        }

        public int getFirstRendered() {
            return firstRendered;
        }

        public void moveCol(int oldIndex, int newIndex) {

            // loop all rows and move given index to its new place
            final Iterator rows = iterator();
            while (rows.hasNext()) {
                ((IScrollTableRow) rows.next()).moveCol(oldIndex, newIndex);
            }

        }

        public class IScrollTableRow extends Panel implements ActionOwner,
                Container {

            protected Vector childWidgets = new Vector();
            private boolean selected = false;
            private final int rowKey;
            private List<UIDL> pendingComponentPaints;

            protected String[] actionKeys = null;

            protected Map widgetColumns = null;

            protected IScrollTableRow(int rowKey) {
                this.rowKey = rowKey;
                setElement(DOM.createElement("tr"));
                DOM.sinkEvents(getElement(), Event.ONCLICK | Event.ONDBLCLICK
                        | Event.ONCONTEXTMENU);
            }

            private void paintComponent(Paintable p, UIDL uidl) {
                if (isAttached()) {
                    p.updateFromUIDL(uidl, client);
                } else {
                    if (pendingComponentPaints == null) {
                        pendingComponentPaints = new LinkedList<UIDL>();
                    }
                    pendingComponentPaints.add(uidl);
                }
            }

            @Override
            protected void onAttach() {
                super.onAttach();
                if (pendingComponentPaints != null) {
                    for (UIDL uidl : pendingComponentPaints) {
                        Paintable paintable = client.getPaintable(uidl);
                        paintable.updateFromUIDL(uidl, client);
                    }
                }
            }

            public String getKey() {
                return String.valueOf(rowKey);
            }

            public IScrollTableRow(UIDL uidl, char[] aligns) {
                this(uidl.getIntAttribute("key"));

                String rowStyle = uidl.getStringAttribute("rowstyle");
                if (rowStyle != null) {
                    addStyleName(CLASSNAME + "-row-" + rowStyle);
                }

                tHead.getColumnAlignments();
                int col = 0;

                // row header
                if (showRowHeaders) {
                    addCell(buildCaptionHtmlSnippet(uidl), aligns[col], "", col,
                            true);
                    col++;
                }

                if (uidl.hasAttribute("al")) {
                    actionKeys = uidl.getStringArrayAttribute("al");
                }

                addCells(uidl, col);

                if (uidl.hasAttribute("selected") && !isSelected()) {
                    toggleSelection();
                }
            }

            protected void addCells(UIDL uidl, int col) {
                int visibleColumnIndex = 0;
                final Iterator cells = uidl.getChildIterator();
                while (cells.hasNext()) {
                    final Object cell = cells.next();

                    String columnId = visibleColOrder[visibleColumnIndex++];

                    String style = "";
                    if (uidl.hasAttribute("style-" + columnId)) {
                        style = uidl.getStringAttribute("style-" + columnId);
                    }

                    if (cell instanceof String) {
                        addCell(cell.toString(), aligns[col], style, col, false);

                    } else {
                        final Paintable cellContent = client
                                .getPaintable((UIDL) cell);

                        addCell((Widget) cellContent, aligns[col], style, col);
                        paintComponent(cellContent, (UIDL) cell);
                    }
                    col++;
                }
            }

            public void addCell(String text, char align, String style, int col,
                    boolean textIsHTML) {
                // String only content is optimized by not using Label widget
                final Element td = DOM.createTD();
                final Element container = DOM.createDiv();
                String classNameTd = CLASSNAME + "-cell";
                String className = CLASSNAME + "-cell-content";
                if (allowMultiStingCells) {
                    classNameTd += " " + CLASSNAME + "-cell-wrap";
                }
                String classNameTdExt = null;
                if (style != null && !style.equals("")) {
                    className += " " + CLASSNAME + "-cell-content-" + style;
                    classNameTdExt = CLASSNAME + "-cell-" + style;
                }
                if (classNameTdExt != null) {
                    classNameTd += " " + classNameTdExt;
                }
                DOM.setElementProperty(td, "className", classNameTd);
                DOM.setElementProperty(container, "className", className);

                setCellContent(container, text, textIsHTML);
                setCellAlignment(container, align);

                DOM.appendChild(td, container);
                DOM.appendChild(getElement(), td);
            }

            public void addCell(Widget w, char align, String style, int col) {
                final Element td = DOM.createTD();
                final Element container = DOM.createDiv();
                String classNameTd = CLASSNAME + "-cell";
                String className = CLASSNAME + "-cell-content";
                if (allowMultiStingCells) {
                    classNameTd += " " + CLASSNAME + "-cell-wrap";
                }
                String classNameTdExt = null;
                if (style != null && !style.equals("")) {
                    className += " " + CLASSNAME + "-cell-content-" + style;
                    classNameTdExt = CLASSNAME + "-cell-" + style;
                }
                if (classNameTdExt != null) {
                    classNameTd += " " + classNameTdExt;
                }
                DOM.setElementProperty(td, "className", classNameTd);
                DOM.setElementProperty(container, "className", className);
                // TODO most components work with this, but not all (e.g.
                // Select)
                // Old comment: make widget cells respect align.
                // text-align:center for IE, margin: auto for others

                setCellAlignment(container, align);

                DOM.appendChild(td, container);
                DOM.appendChild(getElement(), td);

                setCellContent(container, w, col);
            }

            protected void moveCol(int oldIndex, int newIndex) {
                final Element td = DOM.getChild(getElement(), oldIndex);
                DOM.removeChild(getElement(), td);

                DOM.insertChild(getElement(), td, newIndex);
            }

            protected void setCellContent(Element container, String text,
                                          boolean textIsHTML) {
                if (textIsHTML) {
                    Tools.setInnerHTML(container, text);
                } else {
                    Tools.setInnerText(container, text);
                }
            }

            public int getHeight() {
                return DOM.getChild(getElement(), 0).getOffsetHeight();
            }

            protected void setCellContent(Element container, Widget w, int colIndex) {
                // ensure widget not attached to another element (possible tBody
                // change)
                w.removeFromParent();
                DOM.appendChild(container, w.getElement());
                adopt(w);
                childWidgets.add(w);
                if (widgetColumns == null) {
                    widgetColumns = new HashMap();
                }
                widgetColumns.put(w, colIndex);
            }

            protected void setCellAlignment(Element container, char align) {
                if (align != ALIGN_LEFT) {
                    switch (align) {
                    case ALIGN_CENTER:
                        DOM.setStyleAttribute(container, "textAlign", "center");
                        break;
                    case ALIGN_RIGHT:
                    default:
                        DOM.setStyleAttribute(container, "textAlign", "right");
                        break;
                    }
                }
            }

            public Iterator iterator() {
                return childWidgets.iterator();
            }

            @Override
            public boolean remove(Widget w) {
                if (childWidgets.contains(w)) {
                    orphan(w);
                    DOM.removeChild(DOM.getParent(w.getElement()), w
                            .getElement());
                    childWidgets.remove(w);
                    if (widgetColumns != null) {
                        widgetColumns.remove(w);
                    }
                    return true;
                } else {
                    return false;
                }
            }

            protected void handleClickEvent(Event event) {
                if (emitClickEvents) {
                    boolean dbl = DOM.eventGetType(event) == Event.ONDBLCLICK;
                    final Element tdOrTr = DOM.getParent(DOM
                            .eventGetTarget(event));
                    client.updateVariable(paintableId, "clickedKey", ""
                            + rowKey, false);
                    if (getElement() == tdOrTr.getParentElement()) {
                        int childIndex = DOM
                                .getChildIndex(getElement(), tdOrTr);
                        String colKey = tHead.getHeaderCell(childIndex).getColKey();
                        client.updateVariable(paintableId, "clickedColKey",
                                colKey, false);
                    }
                    MouseEventDetails details = new MouseEventDetails(event);
                    // Note: the 'immediate' logic would need to be more
                    // involved (see #2104), but iscrolltable always sends
                    // select event, even though nullselectionallowed wont let
                    // the change trough. Will need to be updated if that is
                    // changed.
                    client
                            .updateVariable(
                                    paintableId,
                                    "clickEvent",
                                    details.toString(),
                                    (dbl || selectMode > Table.SELECT_MODE_NONE || immediate));
                }
            }

            /*
             * React on click that occur on content cells only
             */
            @Override
            public void onBrowserEvent(Event event) {
//                final Element tdOrTr = DOM.getParent(DOM.eventGetTarget(event));
//                if (getElement() == tdOrTr
//                        || getElement() == tdOrTr.getParentElement()) {
                final Element targetElement = DOM.eventGetTarget(event);
                //todo gorodnov: review this code when we will be use a multi selection
                if (Tools.isCheckbox(targetElement) || Tools.isRadio(targetElement))
                    return;

                switch (DOM.eventGetType(event)) {
                case Event.ONCLICK:
                    handleClickEvent(event);
                    handleRowClick(event);
                    break;
                case Event.ONDBLCLICK:
                    handleClickEvent(event);
                    break;
                case Event.ONCONTEXTMENU:
                    handleRowClick(event);
                    showContextMenu(event);
                    break;
                default:
                    break;
                }
//                }
                super.onBrowserEvent(event);
            }

            protected void handleRowClick(Event event) {
                if (selectMode > Table.SELECT_MODE_NONE) {
                    if (!nullSelectionDisallowed || !isSelected()) {
                        toggleSelection();
                        // Note: changing the immediateness of this might
                        // require changes to "clickEvent" immediateness
                        // also.
                        client.updateVariable(paintableId, "selected",
                                selectedRowKeys.toArray(), immediate);
                    }
                }
            }

            public void showContextMenu(Event event) {
                if (enabled && actionKeys != null && actionKeys.length > 0) {
                    int left = event.getClientX();
                    int top = event.getClientY();
                    top += Window.getScrollTop();
                    left += Window.getScrollLeft();
                    client.getContextMenu().showAt(this, left, top);
                }
                event.cancelBubble(true);
                event.preventDefault();
            }

            public boolean isSelected() {
                return selected;
            }

            protected void toggleSelection() {
                selected = !selected;
                if (selected) {
                    if (selectMode == Table.SELECT_MODE_SINGLE) {
                        deselectAll();
                    }
                    selectedRowKeys.add(String.valueOf(rowKey));
                    addStyleName("i-selected");
                } else {
                    selectedRowKeys.remove(String.valueOf(rowKey));
                    removeStyleName("i-selected");
                }
            }

            /*
             * (non-Javadoc)
             *
             * @see
             * com.itmill.toolkit.terminal.gwt.client.ui.IActionOwner#getActions
             * ()
             */
            public Action[] getActions() {
                if (actionKeys == null) {
                    return new Action[] {};
                }
                final Action[] actions = new Action[actionKeys.length];
                for (int i = 0; i < actions.length; i++) {
                    final String actionKey = actionKeys[i];
                    final TreeAction a = new TreeAction(this, String
                            .valueOf(rowKey), actionKey);
                    a.setCaption(getActionCaption(actionKey));
                    a.setIconUrl(getActionIcon(actionKey));
                    actions[i] = a;
                }
                return actions;
            }

            public ApplicationConnection getClient() {
                return client;
            }

            public String getPaintableId() {
                return paintableId;
            }

            public RenderSpace getAllocatedSpace(Widget child) {
                int w = 0;
                int i = getColIndexOf(child);
                HeaderCell headerCell = tHead.getHeaderCell(i);
                if (headerCell != null) {
                    if (initializedAndAttached) {
                        w = headerCell.getWidth() - CELL_CONTENT_PADDING;
                    } else {
                        // header offset width is not absolutely correct value,
                        // but
                        // a best guess (expecting similar content in all
                        // columns ->
                        // if one component is relative width so are others)
                        w = headerCell.getOffsetWidth() - CELL_CONTENT_PADDING;
                    }
                }
                return new RenderSpace(w, getRowHeight());
            }

            protected int getColIndexOf(Widget child) {
                int index = -1;
                if (widgetColumns != null) {
                    Integer i = (Integer) widgetColumns.get(child);
                    if (i != null) {
                        index = i;
                    }
                }
                return index;
            }

            public boolean hasChildComponent(Widget component) {
                return childWidgets.contains(component);
            }

            public void replaceChildComponent(Widget oldComponent,
                    Widget newComponent) {
                com.google.gwt.dom.client.Element parentElement = oldComponent
                        .getElement().getParentElement();
                int index = childWidgets.indexOf(oldComponent);
                oldComponent.removeFromParent();

                parentElement.appendChild(newComponent.getElement());
                childWidgets.insertElementAt(newComponent, index);
                if (widgetColumns == null) {
                    widgetColumns = new HashMap();
                }
                widgetColumns.remove(oldComponent);
                widgetColumns.put(newComponent, index);
                adopt(newComponent);

            }

            public boolean requestLayout(Set<Paintable> children) {
                // row size should never change and system wouldn't event
                // survive as this is a kind of fake paitable
                return true;
            }

            public void updateCaption(Paintable component, UIDL uidl) {
                // NOP, not rendered
            }

            public void updateFromUIDL(UIDL uidl, ApplicationConnection client) {
                // Should never be called,
                // Component container interface faked here to get layouts
                // render properly
            }
        }
    }

    public void deselectAll() {
        final Object[] keys = selectedRowKeys.toArray();
        for (int i = 0; i < keys.length; i++) {
            final IScrollTableBody.IScrollTableRow row = getRenderedRowByKey((String) keys[i]);
            if (row != null && row.isSelected()) {
                row.toggleSelection();
            }
        }
        // still ensure all selects are removed from (not necessary rendered)
        selectedRowKeys.clear();

    }

    @Override
    public void setWidth(String width) {
        if (this.width.equals(width)) {
            return;
        }

        this.width = width;
        if (width != null && !"".equals(width)) {
            int oldWidth = getOffsetWidth();
            super.setWidth(width);
            int newWidth = getOffsetWidth();

            if (scrollbarWidthReservedInColumn != -1 && oldWidth > newWidth
                    && (oldWidth - newWidth) < scrollbarWidthReserved) {
                int col = scrollbarWidthReservedInColumn;
                String colKey = getColKeyByIndex(col);
                setColWidth(scrollbarWidthReservedInColumn, getColWidth(colKey)
                        - (oldWidth - newWidth));
                scrollbarWidthReservedInColumn = -1;
            }

            int innerPixels = getOffsetWidth() - getBorderWidth();
            if (innerPixels < 0) {
                innerPixels = 0;
            }
            setContentWidth(innerPixels);
        } else {
            super.setWidth("");
        }
    }

    /**
     * helper to set pixel size of head and body part
     *
     * @param pixels
     */
    protected void setContentWidth(int pixels) {
        tHead.setWidth(pixels + "px");
        bodyContainer.setWidth(pixels + "px");
    }

    private int borderWidth = -1;

    /**
     * @return border left + border right
     */
    private int getBorderWidth() {
        if (borderWidth < 0) {
            borderWidth = Util.measureHorizontalPaddingAndBorder(bodyContainer
                    .getElement(), 2);
            if (borderWidth < 0) {
                borderWidth = 0;
            }
        }
        return borderWidth;
    }

    /**
     * Ensures scrollable area is properly sized.
     */
    private void setContainerHeight() {
        if (height != null && !"".equals(height)) {
            int contentH = getOffsetHeight() - tHead.getOffsetHeight();
            contentH -= getContentAreaBorderHeight();
            if (contentH < 0) {
                contentH = 0;
            }
            bodyContainer.setHeight(contentH + "px");
        }
    }

    private int contentAreaBorderHeight = -1;

    /**
     * @return border top + border bottom of the scrollable area of table
     */
    private int getContentAreaBorderHeight() {
        if (contentAreaBorderHeight < 0) {
            DOM.setStyleAttribute(bodyContainer.getElement(), "overflow",
                    "hidden");
            contentAreaBorderHeight = bodyContainer.getOffsetHeight()
                    - bodyContainer.getElement().getPropertyInt("clientHeight");
            DOM.setStyleAttribute(bodyContainer.getElement(), "overflow",
                    "auto");
        }
        return contentAreaBorderHeight;
    }

    @Override
    public void setHeight(String height) {
        this.height = height;
        super.setHeight(height);
        setContainerHeight();
    }

    /*
     * Overridden due Table might not survive of visibility change (scroll pos
     * lost). Example ITabPanel just set contained components invisible and back
     * when changing tabs.
     */
    @Override
    public void setVisible(boolean visible) {
        if (isVisible() != visible) {
            super.setVisible(visible);
            if (initializedAndAttached) {
                if (visible) {
                    DeferredCommand.addCommand(new Command() {
                        public void execute() {
                            bodyContainer.setScrollPosition(firstRowInViewPort
                                    * tBody.getRowHeight());
                        }
                    });
                }
            }
        }
    }

    /**
     * Helper function to build html snippet for column or row headers
     *
     * @param uidl
     *            possibly with values caption and icon
     * @return html snippet containing possibly an icon + caption text
     */
    protected String buildCaptionHtmlSnippet(UIDL uidl) {
        String s = uidl.getStringAttribute("caption");
        if (uidl.hasAttribute("icon")) {
            s = "<img src=\""
                    + client.translateToolkitUri(uidl
                            .getStringAttribute("icon"))
                    + "\" alt=\"icon\" class=\"i-icon\">" + s;
        }
        return s;
    }

}