package androidx.compose.ui.semantics;

import androidx.compose.ui.text.C0995g;
import kotlin.collections.A;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.K;

/* loaded from: classes.dex */
public abstract class t {
    public static final /* synthetic */ kotlin.reflect.n[] a;

    static {
        kotlin.jvm.internal.v vVar = new kotlin.jvm.internal.v(t.class, "stateDescription", "getStateDescription(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Ljava/lang/String;", 1);
        K.a.getClass();
        a = new kotlin.reflect.n[]{vVar, new kotlin.jvm.internal.v(t.class, "progressBarRangeInfo", "getProgressBarRangeInfo(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/semantics/ProgressBarRangeInfo;", 1), new kotlin.jvm.internal.v(t.class, "paneTitle", "getPaneTitle(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Ljava/lang/String;", 1), new kotlin.jvm.internal.v(t.class, "liveRegion", "getLiveRegion(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)I", 1), new kotlin.jvm.internal.v(t.class, "focused", "getFocused(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "isContainer", "isContainer(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "isTraversalGroup", "isTraversalGroup(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "contentType", "getContentType(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/autofill/ContentType;", 1), new kotlin.jvm.internal.v(t.class, "contentDataType", "getContentDataType(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)I", 1), new kotlin.jvm.internal.v(t.class, "traversalIndex", "getTraversalIndex(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)F", 1), new kotlin.jvm.internal.v(t.class, "horizontalScrollAxisRange", "getHorizontalScrollAxisRange(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/semantics/ScrollAxisRange;", 1), new kotlin.jvm.internal.v(t.class, "verticalScrollAxisRange", "getVerticalScrollAxisRange(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/semantics/ScrollAxisRange;", 1), new kotlin.jvm.internal.v(t.class, "role", "getRole(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)I", 1), new kotlin.jvm.internal.v(t.class, "testTag", "getTestTag(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Ljava/lang/String;", 1), new kotlin.jvm.internal.v(t.class, "textSubstitution", "getTextSubstitution(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/text/AnnotatedString;", 1), new kotlin.jvm.internal.v(t.class, "isShowingTextSubstitution", "isShowingTextSubstitution(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "editableText", "getEditableText(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/text/AnnotatedString;", 1), new kotlin.jvm.internal.v(t.class, "textSelectionRange", "getTextSelectionRange(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)J", 1), new kotlin.jvm.internal.v(t.class, "imeAction", "getImeAction(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)I", 1), new kotlin.jvm.internal.v(t.class, "selected", "getSelected(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "collectionInfo", "getCollectionInfo(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/semantics/CollectionInfo;", 1), new kotlin.jvm.internal.v(t.class, "collectionItemInfo", "getCollectionItemInfo(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/semantics/CollectionItemInfo;", 1), new kotlin.jvm.internal.v(t.class, "toggleableState", "getToggleableState(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/compose/ui/state/ToggleableState;", 1), new kotlin.jvm.internal.v(t.class, "isEditable", "isEditable(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Z", 1), new kotlin.jvm.internal.v(t.class, "maxTextLength", "getMaxTextLength(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)I", 1), new kotlin.jvm.internal.v(t.class, "customActions", "getCustomActions(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Ljava/util/List;", 1)};
        u uVar = r.a;
        u uVar2 = j.a;
    }

    public static final u a(String str) {
        u uVar = new u(str);
        uVar.c = true;
        return uVar;
    }

    public static final u b(String str, Function2 function2) {
        return new u(str, true, function2);
    }

    public static void c(v vVar, Function1 function1) {
        ((k) vVar).b(j.a, new a(null, function1));
    }

    public static final void d(v vVar) {
        u uVar = r.l;
        kotlin.reflect.n nVar = a[5];
        uVar.a(vVar, Boolean.TRUE);
    }

    public static final void e(v vVar, String str) {
        u uVar = r.a;
        ((k) vVar).b(r.a, A.b(str));
    }

    public static final void f(v vVar) {
        u uVar = r.j;
        kotlin.reflect.n nVar = a[3];
        uVar.a(vVar, new f());
    }

    public static final void g(v vVar, g gVar) {
        u uVar = r.c;
        kotlin.reflect.n nVar = a[1];
        uVar.a(vVar, gVar);
    }

    public static final void h(v vVar, int i) {
        u uVar = r.s;
        kotlin.reflect.n nVar = a[12];
        uVar.a(vVar, new h(i));
    }

    public static final void i(v vVar, String str) {
        u uVar = r.t;
        kotlin.reflect.n nVar = a[13];
        uVar.a(vVar, str);
    }

    public static final void j(v vVar, C0995g c0995g) {
        u uVar = r.a;
        ((k) vVar).b(r.u, A.b(c0995g));
    }

    public static final void k(v vVar) {
        u uVar = r.l;
        kotlin.reflect.n nVar = a[6];
        uVar.a(vVar, Boolean.TRUE);
    }
}
