package org.wordpress.aztec.source;

import android.text.Editable;
import android.text.TextWatcher;
import android.text.style.CharacterStyle;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import androidx.compose.material3.C0676l1;
import com.google.android.gms.internal.mlkit_vision_camera.K2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class c implements TextWatcher {
    public final int a;
    public final int b;
    public int c;
    public CharSequence d;
    public b e;

    public c(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public static String a(String str) {
        int iHashCode = str.hashCode();
        return iHashCode != 38 ? iHashCode != 62 ? iHashCode != 59 ? (iHashCode == 60 && str.equals(SimpleComparison.LESS_THAN_OPERATION)) ? SimpleComparison.GREATER_THAN_OPERATION : "" : !str.equals(";") ? "" : "&" : !str.equals(SimpleComparison.GREATER_THAN_OPERATION) ? "" : SimpleComparison.LESS_THAN_OPERATION : !str.equals("&") ? "" : ";";
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable content) {
        C0676l1 c0676l1D;
        CharSequence charSequence = this.d;
        if (charSequence == null || content == null) {
            return;
        }
        if (StringsKt.G(charSequence.toString(), SimpleComparison.LESS_THAN_OPERATION, false)) {
            c0676l1D = c(content, SimpleComparison.LESS_THAN_OPERATION);
        } else {
            CharSequence charSequence2 = this.d;
            Intrinsics.d(charSequence2);
            if (StringsKt.G(charSequence2.toString(), SimpleComparison.GREATER_THAN_OPERATION, false)) {
                c0676l1D = b(content, SimpleComparison.GREATER_THAN_OPERATION);
            } else {
                CharSequence charSequence3 = this.d;
                Intrinsics.d(charSequence3);
                if (StringsKt.G(charSequence3.toString(), "&", false)) {
                    c0676l1D = c(content, "&");
                } else {
                    CharSequence charSequence4 = this.d;
                    Intrinsics.d(charSequence4);
                    if (StringsKt.G(charSequence4.toString(), ";", false)) {
                        c0676l1D = b(content, ";");
                    } else {
                        c0676l1D = d(content, SimpleComparison.LESS_THAN_OPERATION);
                        if (c0676l1D == null) {
                            c0676l1D = d(content, "&");
                        }
                    }
                }
            }
        }
        if (c0676l1D != null) {
            int length = content.length();
            int i = c0676l1D.a;
            if (i <= length) {
                int length2 = content.length();
                int length3 = c0676l1D.b;
                if (length3 <= length2) {
                    if (i >= length3) {
                        length3 = content.length();
                        i = 0;
                    }
                    Intrinsics.checkNotNullParameter(content, "content");
                    CharacterStyle[] characterStyleArr = (CharacterStyle[]) content.getSpans(i, length3, CharacterStyle.class);
                    Intrinsics.d(characterStyleArr);
                    ArrayList arrayList = new ArrayList();
                    for (CharacterStyle characterStyle : characterStyleArr) {
                        if ((characterStyle instanceof ForegroundColorSpan) || (characterStyle instanceof StyleSpan) || (characterStyle instanceof RelativeSizeSpan)) {
                            arrayList.add(characterStyle);
                        }
                    }
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        content.removeSpan((CharacterStyle) it2.next());
                    }
                    K2.d(content, i, length3, this.a, this.b);
                }
            }
        }
        this.d = null;
        this.e = b.d;
    }

    public final C0676l1 b(Editable editable, String str) {
        if (this.e == b.c) {
            return new C0676l1(0, editable.length(), false);
        }
        String strA = a(str);
        int i = this.c;
        CharSequence charSequence = this.d;
        Intrinsics.d(charSequence);
        int iM = StringsKt.M(charSequence.toString(), str, 0, false, 6) + i;
        String string = editable.toString();
        int i2 = this.c;
        CharSequence charSequence2 = this.d;
        Intrinsics.d(charSequence2);
        int iM2 = StringsKt.M(string, str, charSequence2.length() + i2, false, 4);
        int iQ = StringsKt.Q(editable.toString(), strA, iM - 1, 4);
        if (iQ >= 0) {
            return iM2 >= 0 ? new C0676l1(iQ, iM2 + 1, false) : new C0676l1(iQ, editable.length(), false);
        }
        return null;
    }

    /*  JADX ERROR: JadxRuntimeException in pass: SimplifyVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't remove SSA var: r0v0 int, still in use, count: 1, list:
          (r0v0 int) from 0x001f: INVOKE (r4v0 java.lang.CharSequence), (wrap:int:0x001e: ARITH (r5v0 int) + (r7v0 int) A[WRAPPED]), (r0v0 int) INTERFACE call: java.lang.CharSequence.subSequence(int, int):java.lang.CharSequence A[MD:(int, int):java.lang.CharSequence (c), WRAPPED]
        	at jadx.core.utils.InsnRemover.removeSsaVar(InsnRemover.java:162)
        	at jadx.core.utils.InsnRemover.unbindResult(InsnRemover.java:127)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:91)
        	at jadx.core.utils.InsnRemover.unbindArgUsage(InsnRemover.java:174)
        	at jadx.core.utils.InsnRemover.unbindAllArgs(InsnRemover.java:106)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:90)
        	at jadx.core.utils.InsnRemover.unbindArgUsage(InsnRemover.java:174)
        	at jadx.core.dex.instructions.args.InsnArg.wrapInstruction(InsnArg.java:141)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyArgs(SimplifyVisitor.java:116)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyInsn(SimplifyVisitor.java:132)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyBlock(SimplifyVisitor.java:86)
        	at jadx.core.dex.visitors.SimplifyVisitor.visit(SimplifyVisitor.java:71)
        */
    @Override // android.text.TextWatcher
    public final void beforeTextChanged(java.lang.CharSequence r4, int r5, int r6, int r7) {
        /*
            r3 = this;
            if (r4 != 0) goto L3
            goto L25
        L3:
            int r0 = r5 + r6
            int r1 = r0 + (-1)
            int r2 = r4.length()
            if (r2 <= r1) goto L25
            if (r1 < 0) goto L25
            if (r7 >= r6) goto L25
            if (r7 <= 0) goto L18
            org.wordpress.aztec.source.b r6 = org.wordpress.aztec.source.b.c
            r3.e = r6
            goto L1c
        L18:
            org.wordpress.aztec.source.b r6 = org.wordpress.aztec.source.b.b
            r3.e = r6
        L1c:
            r3.c = r5
            int r5 = r5 + r7
            java.lang.CharSequence r4 = r4.subSequence(r5, r0)
            r3.d = r4
        L25:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.source.c.beforeTextChanged(java.lang.CharSequence, int, int, int):void");
    }

    public final C0676l1 c(Editable editable, String str) {
        int iM;
        if (this.e == b.c) {
            return new C0676l1(0, editable.length(), false);
        }
        String strA = a(str);
        int i = this.c;
        CharSequence charSequence = this.d;
        Intrinsics.d(charSequence);
        int iM2 = StringsKt.M(charSequence.toString(), str, 0, false, 6) + i;
        if (this.e == b.a) {
            int i2 = this.c;
            CharSequence charSequence2 = this.d;
            Intrinsics.d(charSequence2);
            iM = StringsKt.M(editable.toString(), strA, StringsKt.Q(charSequence2.toString(), str, 0, 6) + i2, false, 4);
        } else {
            iM = StringsKt.M(editable.toString(), strA, this.c, false, 4);
        }
        if (iM > 0) {
            return new C0676l1(iM2, iM + 1, false);
        }
        return null;
    }

    public final C0676l1 d(Editable editable, String str) {
        int iM;
        String strA = a(str);
        int iQ = StringsKt.Q(editable.toString(), str, this.c, 4);
        if (iQ < 0 || (iM = StringsKt.M(editable.toString(), strA, iQ, false, 4)) < this.c) {
            return null;
        }
        return new C0676l1(iQ, iM + 1, false);
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        if (charSequence == null) {
            return;
        }
        int i4 = i + i3;
        if (charSequence.length() <= i4 - 1 || i3 <= 0) {
            return;
        }
        if (i2 > 0) {
            this.e = b.c;
            this.d = charSequence.subSequence(i, i4);
        } else {
            this.e = b.a;
            this.c = i;
            this.d = charSequence.subSequence(i + i2, i4);
        }
    }
}
