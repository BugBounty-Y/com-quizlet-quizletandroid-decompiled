package androidx.camera.camera2.internal.concurrent;

import android.content.ClipData;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import androidx.appcompat.widget.C0116w;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.F;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.camera2.internal.compat.q;
import androidx.camera.core.InitializationException;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.collection.W;
import androidx.collection.Y;
import androidx.compose.foundation.gestures.l1;
import androidx.core.content.FileProvider;
import androidx.core.content.d;
import androidx.fragment.app.Fragment;
import androidx.navigation.A;
import androidx.navigation.B;
import androidx.navigation.D;
import androidx.navigation.internal.n;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1357b0;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.InterfaceC1385p0;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.s7;
import com.quizlet.data.repository.set.f;
import com.quizlet.local.cache.caches.c;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.widgets.y;
import com.quizlet.qutils.image.capture.b;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.serialization.json.internal.e;
import kotlinx.serialization.json.internal.k;

/* loaded from: classes.dex */
public class a implements com.quizlet.background.widget.a {
    public final /* synthetic */ int a;
    public int b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public /* synthetic */ a() {
        this.a = 1;
    }

    public static /* synthetic */ void r(a aVar, String str, int i, String str2, int i2) {
        if ((i2 & 2) != 0) {
            i = aVar.b;
        }
        if ((i2 & 4) != 0) {
            str2 = "";
        }
        aVar.q(i, str, str2);
        throw null;
    }

    public String A(int i) {
        C0116w c0116w = (C0116w) this.c;
        int lineStart = c0116w.getLayout().getLineStart(i);
        int lineEnd = c0116w.getLayout().getLineEnd(i);
        Editable text = c0116w.getText();
        Intrinsics.checkNotNullExpressionValue(text, "getText(...)");
        return text.subSequence(lineStart, lineEnd).toString();
    }

    public View B(int i) {
        return ((C1357b0) this.d).a.getChildAt(i);
    }

    public int C() {
        return ((C1357b0) this.d).a.getChildCount();
    }

    public void D(int i, int i2, Context context, b bVar) {
        if (i == 1000) {
            if (i2 != -1) {
                bVar.onCancel();
                return;
            }
            if (i == 1000) {
                try {
                    context.revokeUriPermission((Uri) this.f, 3);
                    bVar.g((Uri) this.e);
                } finally {
                    this.b = -1;
                    this.e = null;
                    this.f = null;
                }
            }
        }
    }

    public void E(View view) {
        ((ArrayList) this.c).add(view);
        C1357b0 c1357b0 = (C1357b0) this.d;
        F0 f0P = RecyclerView.P(view);
        if (f0P != null) {
            f0P.onEnteredHiddenState(c1357b0.a);
        }
    }

    public void F(Fragment fragment, boolean z) {
        Uri uri;
        Context context = fragment.getContext();
        File fileA = ((com.quizlet.qutils.image.capture.a) this.c).a(context);
        d dVarC = FileProvider.c(context, (String) this.d);
        try {
            String canonicalPath = fileA.getCanonicalPath();
            Map.Entry entry = null;
            for (Map.Entry entry2 : dVarC.b.entrySet()) {
                String path = ((File) entry2.getValue()).getPath();
                if (FileProvider.a(canonicalPath).startsWith(FileProvider.a(path) + '/') && (entry == null || path.length() > ((File) entry.getValue()).getPath().length())) {
                    entry = entry2;
                }
            }
            if (entry == null) {
                throw new IllegalArgumentException(AbstractC0147y.d("Failed to find configured root that contains ", canonicalPath));
            }
            String path2 = ((File) entry.getValue()).getPath();
            Uri uriBuild = new Uri.Builder().scheme("content").authority(dVarC.a).encodedPath(Uri.encode((String) entry.getKey()) + '/' + Uri.encode(path2.endsWith("/") ? canonicalPath.substring(path2.length()) : canonicalPath.substring(path2.length() + 1), "/")).build();
            this.e = Uri.fromFile(fileA);
            this.f = uriBuild;
            this.b = 1000;
            Intent intent = new Intent("android.media.action.IMAGE_CAPTURE");
            if (intent.resolveActivity(context.getPackageManager()) != null && (uri = (Uri) this.f) != null) {
                intent.putExtra("output", uri);
                intent.setClipData(ClipData.newUri(context.getContentResolver(), "photo", (Uri) this.f));
                intent.addFlags(2);
                intent.addFlags(1);
                if (z) {
                    intent.putExtra("android.intent.extras.CAMERA_FACING", 1);
                }
            }
            fragment.startActivityForResult(intent, this.b);
        } catch (IOException unused) {
            throw new IllegalArgumentException("Failed to resolve canonical path for " + fileA);
        }
    }

    public A G(A a, f navDeepLinkRequest, boolean z, B lastVisited) {
        A aM;
        Intrinsics.checkNotNullParameter(navDeepLinkRequest, "navDeepLinkRequest");
        Intrinsics.checkNotNullParameter(lastVisited, "lastVisited");
        ArrayList arrayList = new ArrayList();
        D d = (D) this.c;
        Iterator it2 = d.iterator();
        while (true) {
            n nVar = (n) it2;
            if (!nVar.hasNext()) {
                break;
            }
            B b = (B) nVar.next();
            aM = Intrinsics.b(b, lastVisited) ? null : b.i(navDeepLinkRequest);
            if (aM != null) {
                arrayList.add(aM);
            }
        }
        A a2 = (A) CollectionsKt.W(arrayList);
        D d2 = d.c;
        if (d2 != null && z && !d2.equals(lastVisited)) {
            aM = d2.m(navDeepLinkRequest, d);
        }
        A[] elements = {a, a2, aM};
        Intrinsics.checkNotNullParameter(elements, "elements");
        return (A) CollectionsKt.W(C4933y.z(elements));
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x0078  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean H(android.view.MotionEvent r8) {
        /*
            r7 = this;
            java.lang.String r0 = "event"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r0)
            java.lang.Object r0 = r7.f
            android.view.accessibility.AccessibilityManager r0 = (android.view.accessibility.AccessibilityManager) r0
            boolean r1 = r0.isEnabled()
            r2 = 0
            if (r1 == 0) goto Lac
            boolean r1 = r0.isTouchExplorationEnabled()
            if (r1 != 0) goto L18
            goto Lac
        L18:
            int r1 = r8.getAction()
            r3 = 9
            r4 = -1
            if (r1 != r3) goto L23
            r7.b = r4
        L23:
            int r1 = r8.getAction()
            java.lang.Object r3 = r7.c
            androidx.appcompat.widget.w r3 = (androidx.appcompat.widget.C0116w) r3
            r5 = 10
            if (r1 != r5) goto L50
            float r1 = r8.getX()
            float r5 = r8.getY()
            android.text.Editable r6 = r3.getText()
            android.text.Selection.removeSelection(r6)
            java.lang.Object r6 = r7.e
            java.lang.String r6 = (java.lang.String) r6
            r3.announceForAccessibility(r6)
            android.text.Editable r6 = r3.getText()
            int r1 = r3.getOffsetForPosition(r1, r5)
            android.text.Selection.setSelection(r6, r1)
        L50:
            float r1 = r8.getX()
            float r8 = r8.getY()
            int r8 = r3.getOffsetForPosition(r1, r8)
            if (r8 == r4) goto L78
            android.text.Layout r1 = r3.getLayout()
            int r8 = r1.getLineForOffset(r8)
            java.lang.String r1 = r7.A(r8)
            java.lang.String r5 = com.google.android.gms.internal.mlkit_vision_camera.C2.a
            java.lang.String r6 = ""
            java.lang.String r1 = kotlin.text.D.o(r1, r5, r6, r2)
            boolean r1 = org.apache.commons.lang3.e.b(r1)
            if (r1 == 0) goto L79
        L78:
            r8 = r4
        L79:
            if (r8 == r4) goto La8
            int r1 = r7.b
            if (r1 == r8) goto La8
            boolean r1 = r3.isFocused()
            if (r1 == 0) goto La1
            boolean r1 = r3.isAccessibilityFocused()
            if (r1 != 0) goto L8c
            goto La1
        L8c:
            java.lang.String r1 = r7.A(r8)
            java.lang.String r5 = com.google.android.gms.internal.mlkit_vision_camera.C2.f
            java.lang.Object r6 = r7.d
            java.lang.String r6 = (java.lang.String) r6
            java.lang.String r1 = kotlin.text.D.o(r1, r5, r6, r2)
            r0.interrupt()
            r3.announceForAccessibility(r1)
            goto La6
        La1:
            r0 = 8
            r3.sendAccessibilityEvent(r0)
        La6:
            r7.b = r8
        La8:
            if (r8 == r4) goto Lac
            r8 = 1
            return r8
        Lac:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.concurrent.a.H(android.view.MotionEvent):boolean");
    }

    public String I(String keyToMatch, boolean z) {
        Intrinsics.checkNotNullParameter(keyToMatch, "keyToMatch");
        int i = this.b;
        try {
            if (h() != 6) {
                return null;
            }
            if (!Intrinsics.b(K(z), keyToMatch)) {
                return null;
            }
            this.d = null;
            if (h() != 5) {
                return null;
            }
            return K(z);
        } finally {
            this.b = i;
            this.d = null;
        }
    }

    public byte J() {
        int i = this.b;
        while (true) {
            int iL = L(i);
            if (iL == -1) {
                this.b = iL;
                return (byte) 10;
            }
            char cCharAt = ((String) this.f).charAt(iL);
            if (cCharAt != '\t' && cCharAt != '\n' && cCharAt != '\r' && cCharAt != ' ') {
                this.b = iL;
                return k.h(cCharAt);
            }
            i = iL + 1;
        }
    }

    public String K(boolean z) {
        String strL;
        byte bJ = J();
        if (z) {
            if (bJ != 1 && bJ != 0) {
                return null;
            }
            strL = m();
        } else {
            if (bJ != 1) {
                return null;
            }
            strL = l();
        }
        this.d = strL;
        return strL;
    }

    public int L(int i) {
        if (i < ((String) this.f).length()) {
            return i;
        }
        return -1;
    }

    public void M(Bundle bundle) {
        this.e = (Uri) bundle.getParcelable("ImageCapturer_FileUri");
        this.f = (Uri) bundle.getParcelable("ImageCapturer_ContentUri");
        this.b = bundle.getInt("ImageCapturer_CurrentSelectionMode", -1);
    }

    public void N(Bundle bundle) {
        bundle.putParcelable("ImageCapturer_FileUri", (Uri) this.e);
        bundle.putParcelable("ImageCapturer_ContentUri", (Uri) this.f);
        bundle.putInt("ImageCapturer_CurrentSelectionMode", this.b);
    }

    public void O(String str) {
        int iHashCode;
        if (str == null) {
            iHashCode = 0;
        } else {
            D d = (D) this.c;
            if (str.equals((String) d.b.f)) {
                throw new IllegalArgumentException(("Start destination " + str + " cannot use the same route as the graph " + d).toString());
            }
            if (StringsKt.O(str)) {
                throw new IllegalArgumentException("Cannot have an empty start destination route");
            }
            int i = B.e;
            iHashCode = "android-app://androidx.navigation/".concat(str).hashCode();
        }
        this.b = iHashCode;
        this.f = str;
    }

    public int P() {
        char cCharAt;
        int i = this.b;
        if (i == -1) {
            return i;
        }
        while (true) {
            String str = (String) this.f;
            if (i >= str.length() || !((cCharAt = str.charAt(i)) == ' ' || cCharAt == '\n' || cCharAt == '\r' || cCharAt == '\t')) {
                break;
            }
            i++;
        }
        this.b = i;
        return i;
    }

    public boolean Q() {
        int iP = P();
        String str = (String) this.f;
        if (iP >= str.length() || iP == -1 || str.charAt(iP) != ',') {
            return false;
        }
        this.b++;
        return true;
    }

    public void R(char c) {
        int i = this.b;
        if (i > 0 && c == '\"') {
            try {
                this.b = i - 1;
                String strM = m();
                this.b = i;
                if (Intrinsics.b(strM, "null")) {
                    q(this.b - 1, "Expected string literal but 'null' literal was found", "Use 'coerceInputValues = true' in 'Json {}' builder to coerce nulls if property has a default value.");
                    throw null;
                }
            } catch (Throwable th) {
                this.b = i;
                throw th;
            }
        }
        String strU = k.u(k.h(c));
        int i2 = this.b;
        int i3 = i2 - 1;
        String str = (String) this.f;
        r(this, AbstractC0147y.e("Expected ", strU, ", but had '", (i2 == str.length() || i3 < 0) ? "EOF" : String.valueOf(str.charAt(i3)), "' instead"), i3, null, 4);
        throw null;
    }

    public void S(View view) {
        if (((ArrayList) this.c).remove(view)) {
            C1357b0 c1357b0 = (C1357b0) this.d;
            F0 f0P = RecyclerView.P(view);
            if (f0P != null) {
                f0P.onLeftHiddenState(c1357b0.a);
            }
        }
    }

    public Object T(boolean z, h hVar) {
        if (z) {
            c cVar = (c) this.e;
            cVar.getClass();
            cVar.b = com.quizlet.time.b.a();
        }
        y yVar = (y) this.c;
        yVar.getClass();
        Object objF = s7.f(yVar, (Context) this.d, hVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objF != aVar) {
            objF = Unit.a;
        }
        return objF == aVar ? objF : Unit.a;
    }

    public void a(double d, float f) {
        int length = ((float[]) this.c).length + 1;
        int iBinarySearch = Arrays.binarySearch((double[]) this.d, d);
        if (iBinarySearch < 0) {
            iBinarySearch = (-iBinarySearch) - 1;
        }
        this.d = Arrays.copyOf((double[]) this.d, length);
        this.c = Arrays.copyOf((float[]) this.c, length);
        this.e = new double[length];
        double[] dArr = (double[]) this.d;
        System.arraycopy(dArr, iBinarySearch, dArr, iBinarySearch + 1, (length - iBinarySearch) - 1);
        ((double[]) this.d)[iBinarySearch] = d;
        ((float[]) this.c)[iBinarySearch] = f;
    }

    public void b(View view, int i, boolean z) {
        RecyclerView recyclerView = ((C1357b0) this.d).a;
        int childCount = i < 0 ? recyclerView.getChildCount() : y(i);
        ((l1) this.e).y(childCount, z);
        if (z) {
            E(view);
        }
        recyclerView.addView(view, childCount);
        F0 f0P = RecyclerView.P(view);
        AbstractC1361d0 abstractC1361d0 = recyclerView.m;
        if (abstractC1361d0 != null && f0P != null) {
            abstractC1361d0.onViewAttachedToWindow(f0P);
        }
        ArrayList arrayList = recyclerView.C;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((InterfaceC1385p0) recyclerView.C.get(size)).c(view);
            }
        }
    }

    public int c(int i, CharSequence charSequence) {
        int i2 = i + 4;
        if (i2 < charSequence.length()) {
            ((StringBuilder) this.e).append((char) (v(i + 3, charSequence) + (v(i, charSequence) << 12) + (v(i + 1, charSequence) << 8) + (v(i + 2, charSequence) << 4)));
            return i2;
        }
        this.b = i;
        if (i2 < charSequence.length()) {
            return c(this.b, charSequence);
        }
        r(this, "Unexpected EOF during unicode escape", 0, null, 6);
        throw null;
    }

    public void d(View view, int i, ViewGroup.LayoutParams layoutParams, boolean z) {
        RecyclerView recyclerView = ((C1357b0) this.d).a;
        int childCount = i < 0 ? recyclerView.getChildCount() : y(i);
        ((l1) this.e).y(childCount, z);
        if (z) {
            E(view);
        }
        F0 f0P = RecyclerView.P(view);
        if (f0P != null) {
            if (!f0P.isTmpDetached() && !f0P.shouldIgnore()) {
                StringBuilder sb = new StringBuilder("Called attach on a child which is not detached: ");
                sb.append(f0P);
                throw new IllegalArgumentException(androidx.compose.ui.node.B.c(recyclerView, sb));
            }
            if (RecyclerView.N1) {
                f0P.toString();
            }
            f0P.clearTmpDetachFlag();
        } else if (RecyclerView.M1) {
            StringBuilder sb2 = new StringBuilder("No ViewHolder found for child: ");
            sb2.append(view);
            sb2.append(", index: ");
            sb2.append(childCount);
            throw new IllegalArgumentException(androidx.compose.ui.node.B.c(recyclerView, sb2));
        }
        recyclerView.attachViewToParent(view, childCount, layoutParams);
    }

    public boolean e() {
        int i = this.b;
        if (i == -1) {
            return false;
        }
        while (true) {
            String str = (String) this.f;
            if (i >= str.length()) {
                this.b = i;
                return false;
            }
            char cCharAt = str.charAt(i);
            if (cCharAt != ' ' && cCharAt != '\n' && cCharAt != '\r' && cCharAt != '\t') {
                this.b = i;
                return (cCharAt == ',' || cCharAt == ':' || cCharAt == ']' || cCharAt == '}') ? false : true;
            }
            i++;
        }
    }

    public void f(int i, String str) {
        String str2 = (String) this.f;
        if (str2.length() - i < str.length()) {
            r(this, "Unexpected end of boolean literal", 0, null, 6);
            throw null;
        }
        int length = str.length();
        for (int i2 = 0; i2 < length; i2++) {
            if (str.charAt(i2) != (str2.charAt(i + i2) | ' ')) {
                r(this, "Expected valid boolean literal prefix, but had '" + m() + '\'', 0, null, 6);
                throw null;
            }
        }
        this.b = str.length() + i;
    }

    public String g() {
        j('\"');
        int i = this.b;
        String source = (String) this.f;
        int iL = StringsKt.L(source, '\"', i, false, 4);
        if (iL == -1) {
            m();
            int i2 = this.b;
            r(this, android.support.v4.media.session.a.B("Expected quotation mark '\"', but had '", (i2 == source.length() || i2 < 0) ? "EOF" : String.valueOf(source.charAt(i2)), "' instead"), i2, null, 4);
            throw null;
        }
        int i3 = i;
        while (i3 < iL) {
            if (source.charAt(i3) == '\\') {
                int iL2 = this.b;
                Intrinsics.checkNotNullParameter(source, "source");
                char cCharAt = source.charAt(i3);
                boolean z = false;
                while (cCharAt != '\"') {
                    if (cCharAt == '\\') {
                        ((StringBuilder) this.e).append((CharSequence) source, iL2, i3);
                        int iL3 = L(i3 + 1);
                        if (iL3 == -1) {
                            r(this, "Expected escape sequence to continue, got EOF", 0, null, 6);
                            throw null;
                        }
                        int iC = iL3 + 1;
                        char cCharAt2 = source.charAt(iL3);
                        if (cCharAt2 == 'u') {
                            iC = c(iC, source);
                        } else {
                            char c = cCharAt2 < 'u' ? e.a[cCharAt2] : (char) 0;
                            if (c == 0) {
                                r(this, "Invalid escaped char '" + cCharAt2 + '\'', 0, null, 6);
                                throw null;
                            }
                            ((StringBuilder) this.e).append(c);
                        }
                        iL2 = L(iC);
                        if (iL2 == -1) {
                            r(this, "Unexpected EOF", iL2, null, 4);
                            throw null;
                        }
                    } else {
                        i3++;
                        if (i3 >= source.length()) {
                            ((StringBuilder) this.e).append((CharSequence) source, iL2, i3);
                            iL2 = L(i3);
                            if (iL2 == -1) {
                                r(this, "Unexpected EOF", iL2, null, 4);
                                throw null;
                            }
                        } else {
                            continue;
                            cCharAt = source.charAt(i3);
                        }
                    }
                    i3 = iL2;
                    z = true;
                    cCharAt = source.charAt(i3);
                }
                String string = !z ? source.subSequence(iL2, i3).toString() : o(iL2, i3);
                this.b = i3 + 1;
                return string;
            }
            i3++;
        }
        this.b = iL + 1;
        String strSubstring = source.substring(i, iL);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        return strSubstring;
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x002f, code lost:
    
        r4.b = r3.length();
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0035, code lost:
    
        return 10;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public byte h() {
        /*
            r4 = this;
            int r0 = r4.b
        L2:
            r1 = -1
            r2 = 10
            java.lang.Object r3 = r4.f
            java.lang.String r3 = (java.lang.String) r3
            if (r0 == r1) goto L2f
            int r1 = r3.length()
            if (r0 >= r1) goto L2f
            int r1 = r0 + 1
            char r0 = r3.charAt(r0)
            r3 = 32
            if (r0 == r3) goto L2d
            if (r0 == r2) goto L2d
            r2 = 13
            if (r0 == r2) goto L2d
            r2 = 9
            if (r0 != r2) goto L26
            goto L2d
        L26:
            r4.b = r1
            byte r0 = kotlinx.serialization.json.internal.k.h(r0)
            return r0
        L2d:
            r0 = r1
            goto L2
        L2f:
            int r0 = r3.length()
            r4.b = r0
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.concurrent.a.h():byte");
    }

    public byte i(byte b) {
        byte bH = h();
        if (bH == b) {
            return bH;
        }
        String strU = k.u(b);
        int i = this.b;
        int i2 = i - 1;
        String str = (String) this.f;
        r(this, AbstractC0147y.e("Expected ", strU, ", but had '", (i == str.length() || i2 < 0) ? "EOF" : String.valueOf(str.charAt(i2)), "' instead"), i2, null, 4);
        throw null;
    }

    public void j(char c) {
        int i = this.b;
        if (i == -1) {
            R(c);
            throw null;
        }
        while (true) {
            String str = (String) this.f;
            if (i >= str.length()) {
                this.b = -1;
                R(c);
                throw null;
            }
            int i2 = i + 1;
            char cCharAt = str.charAt(i);
            if (cCharAt != ' ' && cCharAt != '\n' && cCharAt != '\r' && cCharAt != '\t') {
                this.b = i2;
                if (cCharAt == c) {
                    return;
                }
                R(c);
                throw null;
            }
            i = i2;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x0194, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x0195, code lost:
    
        r(r21, "Numeric value overflow", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x019b, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x01a1, code lost:
    
        throw new kotlin.NoWhenBranchMatchedException();
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x01a2, code lost:
    
        if (r20 == false) goto L107;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x01a4, code lost:
    
        return r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x01a9, code lost:
    
        if (r10 == Long.MIN_VALUE) goto L111;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x01ac, code lost:
    
        return -r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x01ad, code lost:
    
        r(r21, "Numeric value overflow", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x01b3, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x01b4, code lost:
    
        r(r21, "Expected numeric literal", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x01b9, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00fa, code lost:
    
        r(r21, "Unexpected symbol '" + r5 + "' in numeric literal", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0113, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x011a, code lost:
    
        if (r12 == r1) goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x011c, code lost:
    
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x011e, code lost:
    
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x011f, code lost:
    
        if (r1 == r12) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0121, code lost:
    
        if (r20 == false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0125, code lost:
    
        if (r1 == (r12 - 1)) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x012d, code lost:
    
        if (r18 == false) goto L84;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x012f, code lost:
    
        if (r3 == false) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0137, code lost:
    
        if (r2.charAt(r12) != '\"') goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0139, code lost:
    
        r12 = r12 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x013c, code lost:
    
        r(r21, "Expected closing quotation mark", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0144, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x0145, code lost:
    
        r(r21, "EOF", 0, null, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x014b, code lost:
    
        throw null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x014c, code lost:
    
        r21.b = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x014e, code lost:
    
        if (r19 == false) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0150, code lost:
    
        r1 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0153, code lost:
    
        if (r15 != false) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0155, code lost:
    
        r3 = java.lang.Math.pow(10.0d, -r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x015d, code lost:
    
        if (r15 != true) goto L103;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x015f, code lost:
    
        r3 = java.lang.Math.pow(10.0d, r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x0164, code lost:
    
        r1 = r1 * r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x0169, code lost:
    
        if (r1 > 9.223372036854776E18d) goto L101;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x016f, code lost:
    
        if (r1 < (-9.223372036854776E18d)) goto L101;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0177, code lost:
    
        if (java.lang.Math.floor(r1) != r1) goto L99;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0179, code lost:
    
        r10 = (long) r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x017b, code lost:
    
        r(r21, "Can't convert " + r1 + " to Long", 0, null, 6);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long k() {
        /*
            Method dump skipped, instructions count: 449
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.concurrent.a.k():long");
    }

    public String l() {
        String str = (String) this.d;
        if (str == null) {
            return g();
        }
        Intrinsics.d(str);
        this.d = null;
        return str;
    }

    public String m() {
        String str = (String) this.d;
        if (str != null) {
            Intrinsics.d(str);
            this.d = null;
            return str;
        }
        int iP = P();
        String str2 = (String) this.f;
        if (iP >= str2.length() || iP == -1) {
            r(this, "EOF", iP, null, 4);
            throw null;
        }
        byte bH = k.h(str2.charAt(iP));
        if (bH == 1) {
            return l();
        }
        if (bH != 0) {
            r(this, "Expected beginning of the string, but got " + str2.charAt(iP), 0, null, 6);
            throw null;
        }
        boolean z = false;
        while (k.h(str2.charAt(iP)) == 0) {
            iP++;
            if (iP >= str2.length()) {
                ((StringBuilder) this.e).append((CharSequence) str2, this.b, iP);
                int iL = L(iP);
                if (iL == -1) {
                    this.b = iP;
                    return o(0, 0);
                }
                iP = iL;
                z = true;
            }
        }
        String string = !z ? str2.subSequence(this.b, iP).toString() : o(this.b, iP);
        this.b = iP;
        return string;
    }

    public String n() {
        String strM = m();
        if (Intrinsics.b(strM, "null")) {
            if (((String) this.f).charAt(this.b - 1) != '\"') {
                r(this, "Unexpected 'null' value instead of string literal", 0, null, 6);
                throw null;
            }
        }
        return strM;
    }

    public String o(int i, int i2) {
        ((StringBuilder) this.e).append((CharSequence) this.f, i, i2);
        StringBuilder sb = (StringBuilder) this.e;
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        sb.setLength(0);
        return string;
    }

    public void p(int i) {
        int iY = y(i);
        ((l1) this.e).F(iY);
        RecyclerView recyclerView = ((C1357b0) this.d).a;
        View childAt = recyclerView.getChildAt(iY);
        if (childAt != null) {
            F0 f0P = RecyclerView.P(childAt);
            if (f0P != null) {
                if (f0P.isTmpDetached() && !f0P.shouldIgnore()) {
                    StringBuilder sb = new StringBuilder("called detach on an already detached child ");
                    sb.append(f0P);
                    throw new IllegalArgumentException(androidx.compose.ui.node.B.c(recyclerView, sb));
                }
                if (RecyclerView.N1) {
                    f0P.toString();
                }
                f0P.addFlags(256);
            }
        } else if (RecyclerView.M1) {
            StringBuilder sb2 = new StringBuilder("No view at offset ");
            sb2.append(iY);
            throw new IllegalArgumentException(androidx.compose.ui.node.B.c(recyclerView, sb2));
        }
        recyclerView.detachViewFromParent(iY);
    }

    public void q(int i, String message, String hint) {
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(hint, "hint");
        String strConcat = hint.length() == 0 ? "" : "\n".concat(hint);
        StringBuilder sbX = android.support.v4.media.session.a.x(message, " at path: ");
        sbX.append(((C0122z) this.c).q());
        sbX.append(strConcat);
        throw k.d(i, sbX.toString(), (String) this.f);
    }

    public B s(int i) {
        return u(i, (D) this.c, null, false);
    }

    public B t(String route, boolean z) {
        Object next;
        D d;
        Intrinsics.checkNotNullParameter(route, "route");
        W w = (W) this.d;
        Intrinsics.checkNotNullParameter(w, "<this>");
        Iterator it2 = kotlin.sequences.n.b(new Y(w, 0)).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            B b = (B) next;
            if (kotlin.text.D.l((String) b.b.f, route, false)) {
                break;
            }
            Intrinsics.checkNotNullParameter(route, "route");
            if (b.b.i(route) != null) {
                break;
            }
        }
        B b2 = (B) next;
        if (b2 != null) {
            return b2;
        }
        if (!z || (d = ((D) this.c).c) == null) {
            return null;
        }
        return d.k(route);
    }

    public String toString() {
        switch (this.a) {
            case 1:
                return "pos =" + Arrays.toString((double[]) this.d) + " period=" + Arrays.toString((float[]) this.c);
            case 3:
                return ((l1) this.e).toString() + ", hidden list:" + ((ArrayList) this.c).size();
            case 7:
                StringBuilder sb = new StringBuilder("JsonReader(source='");
                sb.append(this.f);
                sb.append("', currentPosition=");
                return android.support.v4.media.session.a.q(sb, this.b, ')');
            default:
                return super.toString();
        }
    }

    public B u(int i, B b, B b2, boolean z) {
        W w = (W) this.d;
        B bU = (B) w.d(i);
        if (b2 != null) {
            if (Intrinsics.b(bU, b2) && Intrinsics.b(bU.c, b2.c)) {
                return bU;
            }
            bU = null;
        } else if (bU != null) {
            return bU;
        }
        D d = (D) this.c;
        if (z) {
            Intrinsics.checkNotNullParameter(w, "<this>");
            Iterator it2 = kotlin.sequences.n.b(new Y(w, 0)).iterator();
            while (true) {
                if (!it2.hasNext()) {
                    bU = null;
                    break;
                }
                B b3 = (B) it2.next();
                bU = (!(b3 instanceof D) || Intrinsics.b(b3, b)) ? null : ((D) b3).f.u(i, d, b2, true);
                if (bU != null) {
                    break;
                }
            }
        }
        if (bU != null) {
            return bU;
        }
        D d2 = d.c;
        if (d2 == null || d2.equals(b)) {
            return null;
        }
        D d3 = d.c;
        Intrinsics.d(d3);
        return d3.f.u(i, d, b2, z);
    }

    public int v(int i, CharSequence charSequence) {
        char cCharAt = charSequence.charAt(i);
        if ('0' <= cCharAt && cCharAt < ':') {
            return cCharAt - '0';
        }
        if ('a' <= cCharAt && cCharAt < 'g') {
            return cCharAt - 'W';
        }
        if ('A' <= cCharAt && cCharAt < 'G') {
            return cCharAt - '7';
        }
        r(this, "Invalid toHexChar char '" + cCharAt + "' in unicode escape", 0, null, 6);
        throw null;
    }

    public View w(int i) {
        return ((C1357b0) this.d).a.getChildAt(y(i));
    }

    public int x() {
        return ((C1357b0) this.d).a.getChildCount() - ((ArrayList) this.c).size();
    }

    public int y(int i) {
        if (i < 0) {
            return -1;
        }
        int childCount = ((C1357b0) this.d).a.getChildCount();
        int i2 = i;
        while (i2 < childCount) {
            l1 l1Var = (l1) this.e;
            int iS = i - (i2 - l1Var.s(i2));
            if (iS == 0) {
                while (l1Var.v(i2)) {
                    i2++;
                }
                return i2;
            }
            i2 += iS;
        }
        return -1;
    }

    public String z(String str) {
        HashMap map = (HashMap) this.e;
        if (!map.containsKey(str)) {
            return null;
        }
        for (String str2 : (List) map.get(str)) {
            Iterator it2 = ((ArrayList) this.d).iterator();
            while (it2.hasNext()) {
                InterfaceC0183w interfaceC0183wD = ((InterfaceC0183w) it2.next()).d();
                AbstractC3242q6.c("CameraInfo doesn't contain Camera2 implementation.", interfaceC0183wD instanceof F);
                if (str2.equals(((F) ((F) interfaceC0183wD).c.b).a)) {
                    return str2;
                }
            }
        }
        return null;
    }

    public a(com.quizlet.data.repository.user.a aVar) {
        this.a = 4;
        ArrayList arrayList = (ArrayList) aVar.c;
        int size = arrayList.size();
        this.c = (String[]) ((ArrayList) aVar.b).toArray(new String[size]);
        int size2 = arrayList.size();
        double[] dArr = new double[size2];
        for (int i = 0; i < size2; i++) {
            dArr[i] = ((Double) arrayList.get(i)).doubleValue();
        }
        this.d = dArr;
        ArrayList arrayList2 = (ArrayList) aVar.d;
        int size3 = arrayList2.size();
        double[] dArr2 = new double[size3];
        for (int i2 = 0; i2 < size3; i2++) {
            dArr2[i2] = ((Double) arrayList2.get(i2)).doubleValue();
        }
        this.e = dArr2;
        this.f = new int[size];
        this.b = 0;
    }

    public a(C0116w aztecText) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(aztecText, "aztecText");
        this.c = aztecText;
        String string = aztecText.getContext().getString(R.string.media_item_content_description);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        this.d = string;
        String string2 = aztecText.getContext().getString(R.string.cursor_moved);
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        this.e = string2;
        Object systemService = aztecText.getContext().getSystemService("accessibility");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager");
        this.f = (AccessibilityManager) systemService;
        this.b = -1;
    }

    public a(Context context, c widgetCache, com.quizlet.quizletandroid.managers.h foregroundMonitor, kotlinx.coroutines.internal.d scope) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(widgetCache, "widgetCache");
        Intrinsics.checkNotNullParameter(foregroundMonitor, "foregroundMonitor");
        Intrinsics.checkNotNullParameter(scope, "scope");
        y widget = y.c;
        Intrinsics.checkNotNullParameter(widget, "widget");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(widgetCache, "widgetCache");
        Intrinsics.checkNotNullParameter(foregroundMonitor, "foregroundMonitor");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.c = widget;
        this.d = context;
        this.e = widgetCache;
        this.f = foregroundMonitor;
        E.A(scope, null, null, new com.quizlet.quizletandroid.ui.widgets.F(this, null), 3);
        this.b = 5;
    }

    public a(D graph) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(graph, "graph");
        this.c = graph;
        this.d = new W(0);
    }

    public a(com.quizlet.qutils.image.capture.a aVar) {
        this.a = 6;
        this.b = -1;
        this.c = aVar;
        this.d = "com.quizlet.quizletandroid.fileprovider";
    }

    public a(q qVar) {
        this.a = 0;
        this.b = 0;
        this.e = new HashMap();
        this.f = new HashSet();
        this.c = new ArrayList();
        this.d = new ArrayList();
        Set hashSet = new HashSet();
        try {
            hashSet = qVar.a.g();
        } catch (CameraAccessExceptionCompat unused) {
            AbstractC3053s1.c("Camera2CameraCoordinator", "Failed to get concurrent camera ids");
        }
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            ArrayList arrayList = new ArrayList((Set) it2.next());
            if (arrayList.size() >= 2) {
                String str = (String) arrayList.get(0);
                String str2 = (String) arrayList.get(1);
                try {
                    if (com.facebook.appevents.internal.d.d(qVar, str) && com.facebook.appevents.internal.d.d(qVar, str2)) {
                        ((HashSet) this.f).add(new HashSet(Arrays.asList(str, str2)));
                        HashMap map = (HashMap) this.e;
                        if (!map.containsKey(str)) {
                            map.put(str, new ArrayList());
                        }
                        if (!map.containsKey(str2)) {
                            map.put(str2, new ArrayList());
                        }
                        ((List) map.get(str)).add((String) arrayList.get(1));
                        ((List) map.get(str2)).add((String) arrayList.get(0));
                    }
                } catch (InitializationException unused2) {
                    AbstractC3053s1.f(3, "Camera2CameraCoordinator");
                }
            }
        }
    }

    public a(C1357b0 c1357b0) {
        this.a = 3;
        this.b = 0;
        this.d = c1357b0;
        this.e = new l1(1);
        this.c = new ArrayList();
    }

    public a(String source) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(source, "source");
        C0122z c0122z = new C0122z(22, (char) 0);
        c0122z.c = new Object[8];
        int[] iArr = new int[8];
        for (int i = 0; i < 8; i++) {
            iArr[i] = -1;
        }
        c0122z.d = iArr;
        c0122z.b = -1;
        this.c = c0122z;
        this.e = new StringBuilder();
        this.f = source;
    }
}
