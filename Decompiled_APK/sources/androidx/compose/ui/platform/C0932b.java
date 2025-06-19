package androidx.compose.ui.platform;

import java.text.BreakIterator;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0932b extends androidx.appcompat.app.y {
    public static C0932b f;
    public static C0932b g;
    public static C0932b h;
    public final /* synthetic */ int d;
    public Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0932b(int i) {
        super(3);
        this.d = i;
    }

    @Override // androidx.appcompat.app.y
    public final int[] e(int i) {
        int iF;
        switch (this.d) {
            case 0:
                int length = l().length();
                if (length <= 0 || i >= length) {
                    return null;
                }
                if (i < 0) {
                    i = 0;
                }
                do {
                    BreakIterator breakIterator = (BreakIterator) this.e;
                    if (breakIterator == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    if (breakIterator.isBoundary(i)) {
                        BreakIterator breakIterator2 = (BreakIterator) this.e;
                        if (breakIterator2 == null) {
                            Intrinsics.m("impl");
                            throw null;
                        }
                        int iFollowing = breakIterator2.following(i);
                        if (iFollowing == -1) {
                            return null;
                        }
                        return i(i, iFollowing);
                    }
                    BreakIterator breakIterator3 = (BreakIterator) this.e;
                    if (breakIterator3 == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    i = breakIterator3.following(i);
                } while (i != -1);
                return null;
            case 1:
                if (l().length() <= 0 || i >= l().length()) {
                    return null;
                }
                if (i < 0) {
                    i = 0;
                }
                while (!y(i) && (!y(i) || (i != 0 && y(i - 1)))) {
                    BreakIterator breakIterator4 = (BreakIterator) this.e;
                    if (breakIterator4 == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    i = breakIterator4.following(i);
                    if (i == -1) {
                        return null;
                    }
                }
                BreakIterator breakIterator5 = (BreakIterator) this.e;
                if (breakIterator5 == null) {
                    Intrinsics.m("impl");
                    throw null;
                }
                int iFollowing2 = breakIterator5.following(i);
                if (iFollowing2 == -1 || !x(iFollowing2)) {
                    return null;
                }
                return i(i, iFollowing2);
            default:
                if (l().length() <= 0 || i >= l().length()) {
                    return null;
                }
                androidx.compose.ui.text.style.h hVar = androidx.compose.ui.text.style.h.b;
                if (i < 0) {
                    androidx.compose.ui.text.H h2 = (androidx.compose.ui.text.H) this.e;
                    if (h2 == null) {
                        Intrinsics.m("layoutResult");
                        throw null;
                    }
                    iF = h2.f(0);
                } else {
                    androidx.compose.ui.text.H h3 = (androidx.compose.ui.text.H) this.e;
                    if (h3 == null) {
                        Intrinsics.m("layoutResult");
                        throw null;
                    }
                    int iF2 = h3.f(i);
                    iF = v(iF2, hVar) == i ? iF2 : iF2 + 1;
                }
                androidx.compose.ui.text.H h4 = (androidx.compose.ui.text.H) this.e;
                if (h4 == null) {
                    Intrinsics.m("layoutResult");
                    throw null;
                }
                if (iF >= h4.b.f) {
                    return null;
                }
                return i(v(iF, hVar), v(iF, androidx.compose.ui.text.style.h.a) + 1);
        }
    }

    @Override // androidx.appcompat.app.y
    public final int[] o(int i) {
        int iF;
        switch (this.d) {
            case 0:
                int length = l().length();
                if (length <= 0 || i <= 0) {
                    return null;
                }
                if (i > length) {
                    i = length;
                }
                do {
                    BreakIterator breakIterator = (BreakIterator) this.e;
                    if (breakIterator == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    if (breakIterator.isBoundary(i)) {
                        BreakIterator breakIterator2 = (BreakIterator) this.e;
                        if (breakIterator2 == null) {
                            Intrinsics.m("impl");
                            throw null;
                        }
                        int iPreceding = breakIterator2.preceding(i);
                        if (iPreceding == -1) {
                            return null;
                        }
                        return i(iPreceding, i);
                    }
                    BreakIterator breakIterator3 = (BreakIterator) this.e;
                    if (breakIterator3 == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    i = breakIterator3.preceding(i);
                } while (i != -1);
                return null;
            case 1:
                int length2 = l().length();
                if (length2 <= 0 || i <= 0) {
                    return null;
                }
                if (i > length2) {
                    i = length2;
                }
                while (i > 0 && !y(i - 1) && !x(i)) {
                    BreakIterator breakIterator4 = (BreakIterator) this.e;
                    if (breakIterator4 == null) {
                        Intrinsics.m("impl");
                        throw null;
                    }
                    i = breakIterator4.preceding(i);
                    if (i == -1) {
                        return null;
                    }
                }
                BreakIterator breakIterator5 = (BreakIterator) this.e;
                if (breakIterator5 == null) {
                    Intrinsics.m("impl");
                    throw null;
                }
                int iPreceding2 = breakIterator5.preceding(i);
                if (iPreceding2 == -1 || !y(iPreceding2)) {
                    return null;
                }
                if (iPreceding2 == 0 || !y(iPreceding2 - 1)) {
                    return i(iPreceding2, i);
                }
                return null;
            default:
                if (l().length() <= 0 || i <= 0) {
                    return null;
                }
                int length3 = l().length();
                androidx.compose.ui.text.style.h hVar = androidx.compose.ui.text.style.h.a;
                if (i > length3) {
                    androidx.compose.ui.text.H h2 = (androidx.compose.ui.text.H) this.e;
                    if (h2 == null) {
                        Intrinsics.m("layoutResult");
                        throw null;
                    }
                    iF = h2.f(l().length());
                } else {
                    androidx.compose.ui.text.H h3 = (androidx.compose.ui.text.H) this.e;
                    if (h3 == null) {
                        Intrinsics.m("layoutResult");
                        throw null;
                    }
                    int iF2 = h3.f(i);
                    iF = v(iF2, hVar) + 1 == i ? iF2 : iF2 - 1;
                }
                if (iF < 0) {
                    return null;
                }
                return i(v(iF, androidx.compose.ui.text.style.h.b), v(iF, hVar) + 1);
        }
    }

    public int v(int i, androidx.compose.ui.text.style.h hVar) {
        androidx.compose.ui.text.H h2 = (androidx.compose.ui.text.H) this.e;
        if (h2 == null) {
            Intrinsics.m("layoutResult");
            throw null;
        }
        int i2 = h2.i(i);
        androidx.compose.ui.text.H h3 = (androidx.compose.ui.text.H) this.e;
        if (h3 == null) {
            Intrinsics.m("layoutResult");
            throw null;
        }
        if (hVar != h3.j(i2)) {
            androidx.compose.ui.text.H h4 = (androidx.compose.ui.text.H) this.e;
            if (h4 != null) {
                return h4.i(i);
            }
            Intrinsics.m("layoutResult");
            throw null;
        }
        if (((androidx.compose.ui.text.H) this.e) != null) {
            return r6.e(i, false) - 1;
        }
        Intrinsics.m("layoutResult");
        throw null;
    }

    public void w(String str) {
        switch (this.d) {
            case 0:
                this.b = str;
                BreakIterator breakIterator = (BreakIterator) this.e;
                if (breakIterator != null) {
                    breakIterator.setText(str);
                    return;
                } else {
                    Intrinsics.m("impl");
                    throw null;
                }
            default:
                this.b = str;
                BreakIterator breakIterator2 = (BreakIterator) this.e;
                if (breakIterator2 != null) {
                    breakIterator2.setText(str);
                    return;
                } else {
                    Intrinsics.m("impl");
                    throw null;
                }
        }
    }

    public boolean x(int i) {
        if (i <= 0 || !y(i - 1)) {
            return false;
        }
        return i == l().length() || !y(i);
    }

    public boolean y(int i) {
        if (i < 0 || i >= l().length()) {
            return false;
        }
        return Character.isLetterOrDigit(l().codePointAt(i));
    }
}
