package androidx.navigation.internal;

import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.preference.PreferenceManager;
import androidx.navigation.A;
import androidx.navigation.B;
import androidx.navigation.C1301x;
import androidx.recyclerview.widget.C1354a;
import androidx.recyclerview.widget.C1356b;
import androidx.recyclerview.widget.C1357b0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.room.s;
import com.facebook.o;
import com.google.android.gms.internal.ads.C2329lt;
import com.google.android.gms.internal.ads.Kn;
import com.google.android.gms.internal.ads.Os;
import com.google.android.gms.internal.ads.Yo;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.PriorityQueue;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

/* loaded from: classes.dex */
public final class m {
    public final /* synthetic */ int a;
    public Serializable b;
    public int c;
    public Object d;
    public Serializable e;
    public Object f;
    public Object g;

    public m() {
        this.a = 4;
        this.d = new com.google.android.gms.cloudmessaging.k(9);
    }

    public boolean a() {
        return String.valueOf(true).equalsIgnoreCase((String) this.e);
    }

    public boolean b(int i) {
        ArrayList arrayList = (ArrayList) this.e;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            C1354a c1354a = (C1354a) arrayList.get(i2);
            int i3 = c1354a.a;
            if (i3 != 8) {
                if (i3 == 1) {
                    int i4 = c1354a.b;
                    int i5 = c1354a.d + i4;
                    while (i4 < i5) {
                        if (g(i4, i2 + 1) == i) {
                            return true;
                        }
                        i4++;
                    }
                } else {
                    continue;
                }
            } else {
                if (g(c1354a.d, i2 + 1) == i) {
                    return true;
                }
            }
        }
        return false;
    }

    public void c() {
        ArrayList arrayList = (ArrayList) this.e;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((C1357b0) this.f).a((C1354a) arrayList.get(i));
        }
        m(arrayList);
        this.c = 0;
    }

    public void d() {
        c();
        ArrayList arrayList = (ArrayList) this.b;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            C1354a c1354a = (C1354a) arrayList.get(i);
            int i2 = c1354a.a;
            C1357b0 c1357b0 = (C1357b0) this.f;
            if (i2 == 1) {
                c1357b0.a(c1354a);
                c1357b0.d(c1354a.b, c1354a.d);
            } else if (i2 == 2) {
                c1357b0.a(c1354a);
                int i3 = c1354a.b;
                int i4 = c1354a.d;
                RecyclerView recyclerView = c1357b0.a;
                recyclerView.V(i3, i4, true);
                recyclerView.u1 = true;
                recyclerView.r1.c += i4;
            } else if (i2 == 4) {
                c1357b0.a(c1354a);
                c1357b0.c(c1354a.b, c1354a.d, c1354a.c);
            } else if (i2 == 8) {
                c1357b0.a(c1354a);
                c1357b0.e(c1354a.b, c1354a.d);
            }
        }
        m(arrayList);
        this.c = 0;
    }

    public void e(C1354a c1354a) {
        int i;
        int i2 = c1354a.a;
        if (i2 == 1 || i2 == 8) {
            throw new IllegalArgumentException("should not dispatch add or move for pre layout");
        }
        int iN = n(c1354a.b, i2);
        int i3 = c1354a.b;
        int i4 = c1354a.a;
        if (i4 == 2) {
            i = 0;
        } else {
            if (i4 != 4) {
                throw new IllegalArgumentException("op should be remove or update." + c1354a);
            }
            i = 1;
        }
        int i5 = 1;
        for (int i6 = 1; i6 < c1354a.d; i6++) {
            int iN2 = n((i * i6) + c1354a.b, c1354a.a);
            int i7 = c1354a.a;
            if (i7 == 2 ? iN2 != iN : !(i7 == 4 && iN2 == iN + 1)) {
                C1354a c1354aJ = j(c1354a.c, i7, iN, i5);
                f(c1354aJ, i3);
                c1354aJ.c = null;
                ((androidx.constraintlayout.core.d) this.d).c(c1354aJ);
                if (c1354a.a == 4) {
                    i3 += i5;
                }
                i5 = 1;
                iN = iN2;
            } else {
                i5++;
            }
        }
        Object obj = c1354a.c;
        c1354a.c = null;
        ((androidx.constraintlayout.core.d) this.d).c(c1354a);
        if (i5 > 0) {
            C1354a c1354aJ2 = j(obj, c1354a.a, iN, i5);
            f(c1354aJ2, i3);
            c1354aJ2.c = null;
            ((androidx.constraintlayout.core.d) this.d).c(c1354aJ2);
        }
    }

    public void f(C1354a c1354a, int i) {
        C1357b0 c1357b0 = (C1357b0) this.f;
        c1357b0.a(c1354a);
        int i2 = c1354a.a;
        if (i2 != 2) {
            if (i2 != 4) {
                throw new IllegalArgumentException("only remove and update ops can be dispatched in first pass");
            }
            c1357b0.c(i, c1354a.d, c1354a.c);
        } else {
            int i3 = c1354a.d;
            RecyclerView recyclerView = c1357b0.a;
            recyclerView.V(i, i3, true);
            recyclerView.u1 = true;
            recyclerView.r1.c += i3;
        }
    }

    public int g(int i, int i2) {
        ArrayList arrayList = (ArrayList) this.e;
        int size = arrayList.size();
        while (i2 < size) {
            C1354a c1354a = (C1354a) arrayList.get(i2);
            int i3 = c1354a.a;
            if (i3 == 8) {
                int i4 = c1354a.b;
                if (i4 == i) {
                    i = c1354a.d;
                } else {
                    if (i4 < i) {
                        i--;
                    }
                    if (c1354a.d <= i) {
                        i++;
                    }
                }
            } else {
                int i5 = c1354a.b;
                if (i5 > i) {
                    continue;
                } else if (i3 == 2) {
                    int i6 = c1354a.d;
                    if (i < i5 + i6) {
                        return -1;
                    }
                    i -= i6;
                } else if (i3 == 1) {
                    i += c1354a.d;
                }
            }
            i2++;
        }
        return i;
    }

    public boolean h() {
        return ((ArrayList) this.b).size() > 0;
    }

    public A i(String route) {
        C1301x c1301x;
        Intrinsics.checkNotNullParameter(route, "route");
        u uVar = (u) this.g;
        if (uVar == null || (c1301x = (C1301x) uVar.getValue()) == null) {
            return null;
        }
        int i = B.e;
        String uriString = route != null ? "android-app://androidx.navigation/".concat(route) : "";
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Intrinsics.checkNotNullParameter(uriString, "uriString");
        Uri uri = Uri.parse(uriString);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        Bundle bundleD = c1301x.d(uri, (LinkedHashMap) this.e);
        if (bundleD == null) {
            return null;
        }
        return new A((B) this.d, bundleD, c1301x.l, c1301x.b(uri), false);
    }

    public C1354a j(Object obj, int i, int i2, int i3) {
        C1354a c1354a = (C1354a) ((androidx.constraintlayout.core.d) this.d).a();
        if (c1354a != null) {
            c1354a.a = i;
            c1354a.b = i2;
            c1354a.d = i3;
            c1354a.c = obj;
            return c1354a;
        }
        C1354a c1354a2 = new C1354a();
        c1354a2.a = i;
        c1354a2.b = i2;
        c1354a2.d = i3;
        c1354a2.c = obj;
        return c1354a2;
    }

    public void k(C1354a c1354a) {
        ((ArrayList) this.e).add(c1354a);
        int i = c1354a.a;
        C1357b0 c1357b0 = (C1357b0) this.f;
        if (i == 1) {
            c1357b0.d(c1354a.b, c1354a.d);
            return;
        }
        if (i == 2) {
            int i2 = c1354a.b;
            int i3 = c1354a.d;
            RecyclerView recyclerView = c1357b0.a;
            recyclerView.V(i2, i3, false);
            recyclerView.u1 = true;
            return;
        }
        if (i == 4) {
            c1357b0.c(c1354a.b, c1354a.d, c1354a.c);
        } else if (i == 8) {
            c1357b0.e(c1354a.b, c1354a.d);
        } else {
            throw new IllegalArgumentException("Unknown update op type for " + c1354a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:184:0x00aa A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:185:0x0135 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0121 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:202:0x000d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0090  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void l() {
        /*
            Method dump skipped, instructions count: 692
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.internal.m.l():void");
    }

    public void m(ArrayList arrayList) {
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            C1354a c1354a = (C1354a) arrayList.get(i);
            c1354a.c = null;
            ((androidx.constraintlayout.core.d) this.d).c(c1354a);
        }
        arrayList.clear();
    }

    public int n(int i, int i2) {
        int i3;
        int i4;
        ArrayList arrayList = (ArrayList) this.e;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            C1354a c1354a = (C1354a) arrayList.get(size);
            int i5 = c1354a.a;
            if (i5 == 8) {
                int i6 = c1354a.b;
                int i7 = c1354a.d;
                if (i6 < i7) {
                    i4 = i6;
                    i3 = i7;
                } else {
                    i3 = i6;
                    i4 = i7;
                }
                if (i < i4 || i > i3) {
                    if (i < i6) {
                        if (i2 == 1) {
                            c1354a.b = i6 + 1;
                            c1354a.d = i7 + 1;
                        } else if (i2 == 2) {
                            c1354a.b = i6 - 1;
                            c1354a.d = i7 - 1;
                        }
                    }
                } else if (i4 == i6) {
                    if (i2 == 1) {
                        c1354a.d = i7 + 1;
                    } else if (i2 == 2) {
                        c1354a.d = i7 - 1;
                    }
                    i++;
                } else {
                    if (i2 == 1) {
                        c1354a.b = i6 + 1;
                    } else if (i2 == 2) {
                        c1354a.b = i6 - 1;
                    }
                    i--;
                }
            } else {
                int i8 = c1354a.b;
                if (i8 <= i) {
                    if (i5 == 1) {
                        i -= c1354a.d;
                    } else if (i5 == 2) {
                        i += c1354a.d;
                    }
                } else if (i2 == 1) {
                    c1354a.b = i8 + 1;
                } else if (i2 == 2) {
                    c1354a.b = i8 - 1;
                }
            }
        }
        for (int size2 = arrayList.size() - 1; size2 >= 0; size2--) {
            C1354a c1354a2 = (C1354a) arrayList.get(size2);
            if (c1354a2.a == 8) {
                int i9 = c1354a2.d;
                if (i9 == c1354a2.b || i9 < 0) {
                    arrayList.remove(size2);
                    c1354a2.c = null;
                    ((androidx.constraintlayout.core.d) this.d).c(c1354a2);
                }
            } else if (c1354a2.d <= 0) {
                arrayList.remove(size2);
                c1354a2.c = null;
                ((androidx.constraintlayout.core.d) this.d).c(c1354a2);
            }
        }
        return i;
    }

    public void o() {
        SharedPreferences.Editor editorEdit = PreferenceManager.getDefaultSharedPreferences(o.a()).edit();
        Long l = (Long) this.d;
        editorEdit.putLong("com.facebook.appevents.SessionInfo.sessionStartTime", l != null ? l.longValue() : 0L);
        Long l2 = (Long) this.b;
        editorEdit.putLong("com.facebook.appevents.SessionInfo.sessionEndTime", l2 != null ? l2.longValue() : 0L);
        editorEdit.putInt("com.facebook.appevents.SessionInfo.interruptionCount", this.c);
        editorEdit.putString("com.facebook.appevents.SessionInfo.sessionId", ((UUID) this.e).toString());
        editorEdit.apply();
        s sVar = (s) this.g;
        if (sVar == null || sVar == null) {
            return;
        }
        SharedPreferences.Editor editorEdit2 = PreferenceManager.getDefaultSharedPreferences(o.a()).edit();
        editorEdit2.putString("com.facebook.appevents.SourceApplicationInfo.callingApplicationPackage", sVar.b);
        editorEdit2.putBoolean("com.facebook.appevents.SourceApplicationInfo.openedByApplink", sVar.c);
        editorEdit2.apply();
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x001f, code lost:
    
        if (r8 < r0.b) goto L33;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void p(long r8, com.google.android.gms.internal.ads.Kn r10) {
        /*
            r7 = this;
            int r0 = r7.c
            if (r0 == 0) goto L9f
            java.lang.Object r1 = r7.f
            java.util.PriorityQueue r1 = (java.util.PriorityQueue) r1
            r2 = -1
            if (r0 == r2) goto L23
            int r0 = r1.size()
            int r3 = r7.c
            if (r0 < r3) goto L23
            java.lang.Object r0 = r1.peek()
            com.google.android.gms.internal.ads.lt r0 = (com.google.android.gms.internal.ads.C2329lt) r0
            java.lang.String r3 = com.google.android.gms.internal.ads.Yo.a
            long r3 = r0.b
            int r0 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            if (r0 >= 0) goto L23
            goto L9f
        L23:
            java.io.Serializable r0 = r7.b
            java.util.ArrayDeque r0 = (java.util.ArrayDeque) r0
            boolean r3 = r0.isEmpty()
            if (r3 == 0) goto L33
            com.google.android.gms.internal.ads.Kn r0 = new com.google.android.gms.internal.ads.Kn
            r0.<init>()
            goto L39
        L33:
            java.lang.Object r0 = r0.pop()
            com.google.android.gms.internal.ads.Kn r0 = (com.google.android.gms.internal.ads.Kn) r0
        L39:
            int r3 = r10.s()
            r0.g(r3)
            byte[] r3 = r10.a
            int r10 = r10.b
            byte[] r4 = r0.a
            int r5 = r0.s()
            r6 = 0
            java.lang.System.arraycopy(r3, r10, r4, r6, r5)
            java.lang.Object r10 = r7.g
            com.google.android.gms.internal.ads.lt r10 = (com.google.android.gms.internal.ads.C2329lt) r10
            if (r10 == 0) goto L61
            long r3 = r10.b
            int r3 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            if (r3 == 0) goto L5b
            goto L61
        L5b:
            java.util.ArrayList r8 = r10.a
            r8.add(r0)
            return
        L61:
            java.io.Serializable r10 = r7.e
            java.util.ArrayDeque r10 = (java.util.ArrayDeque) r10
            boolean r3 = r10.isEmpty()
            if (r3 == 0) goto L71
            com.google.android.gms.internal.ads.lt r10 = new com.google.android.gms.internal.ads.lt
            r10.<init>()
            goto L77
        L71:
            java.lang.Object r10 = r10.pop()
            com.google.android.gms.internal.ads.lt r10 = (com.google.android.gms.internal.ads.C2329lt) r10
        L77:
            r3 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r3 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            if (r3 == 0) goto L81
            r6 = 1
        L81:
            com.google.android.gms.internal.ads.AbstractC1795We.B(r6)
            java.util.ArrayList r3 = r10.a
            boolean r4 = r3.isEmpty()
            com.google.android.gms.internal.ads.AbstractC1795We.L(r4)
            r10.b = r8
            r3.add(r0)
            r1.add(r10)
            r7.g = r10
            int r8 = r7.c
            if (r8 == r2) goto L9e
            r7.q(r8)
        L9e:
            return
        L9f:
            java.lang.Object r0 = r7.d
            com.google.android.gms.internal.ads.Os r0 = (com.google.android.gms.internal.ads.Os) r0
            r0.i(r8, r10)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.navigation.internal.m.p(long, com.google.android.gms.internal.ads.Kn):void");
    }

    public void q(int i) {
        ArrayList arrayList;
        while (true) {
            PriorityQueue priorityQueue = (PriorityQueue) this.f;
            if (priorityQueue.size() <= i) {
                return;
            }
            C2329lt c2329lt = (C2329lt) priorityQueue.poll();
            String str = Yo.a;
            int i2 = 0;
            while (true) {
                arrayList = c2329lt.a;
                if (i2 >= arrayList.size()) {
                    break;
                }
                ((Os) this.d).i(c2329lt.b, (Kn) arrayList.get(i2));
                ((ArrayDeque) this.b).push((Kn) arrayList.get(i2));
                i2++;
            }
            arrayList.clear();
            C2329lt c2329lt2 = (C2329lt) this.g;
            if (c2329lt2 != null && c2329lt2.b == c2329lt.b) {
                this.g = null;
            }
            ((ArrayDeque) this.e).push(c2329lt);
        }
    }

    public String toString() {
        switch (this.a) {
            case 4:
                StringBuilder sb = new StringBuilder("TextProperty{fontProperty=");
                sb.append((com.google.android.gms.cloudmessaging.k) this.d);
                sb.append(", textAlignment='");
                sb.append((String) this.f);
                sb.append("', textColor='");
                sb.append((String) this.b);
                sb.append("', showText='");
                sb.append((String) this.e);
                sb.append("', text='");
                sb.append((String) this.g);
                sb.append("', visibility='");
                return android.support.v4.media.session.a.r(sb, this.c, "'}");
            default:
                return super.toString();
        }
    }

    public m(Os os) {
        this.a = 3;
        this.d = os;
        this.b = new ArrayDeque();
        this.e = new ArrayDeque();
        this.f = new PriorityQueue();
        this.c = -1;
    }

    public m(Long l, Long l2) {
        this.a = 2;
        UUID sessionId = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(sessionId, "randomUUID()");
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        this.d = l;
        this.b = l2;
        this.e = sessionId;
    }

    public m(B destination) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(destination, "destination");
        this.d = destination;
        this.b = new ArrayList();
        this.e = new LinkedHashMap();
    }

    public m(C1357b0 c1357b0) {
        this.a = 1;
        this.d = new androidx.constraintlayout.core.d(30);
        this.b = new ArrayList();
        this.e = new ArrayList();
        this.c = 0;
        this.f = c1357b0;
        this.g = new C1356b(this);
    }
}
