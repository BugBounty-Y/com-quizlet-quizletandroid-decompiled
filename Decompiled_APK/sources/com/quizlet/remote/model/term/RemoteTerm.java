package com.quizlet.remote.model.term;

import androidx.compose.animation.d0;
import com.quizlet.remote.util.JsonString;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteTerm {
    public final long a;
    public final long b;
    public final int c;
    public final String d;
    public final String e;
    public final String f;
    public final Long g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;

    public RemoteTerm(long j, long j2, int i, @NotNull String word, String str, @InterfaceC4853h(name = "_imageUrl") String str2, @InterfaceC4853h(name = "clientId") Long l, @JsonString String str3, @JsonString String str4, @InterfaceC4853h(name = "_wordAudioUrl") String str5, @InterfaceC4853h(name = "_definitionAudioUrl") String str6) {
        Intrinsics.checkNotNullParameter(word, "word");
        this.a = j;
        this.b = j2;
        this.c = i;
        this.d = word;
        this.e = str;
        this.f = str2;
        this.g = l;
        this.h = str3;
        this.i = str4;
        this.j = str5;
        this.k = str6;
    }

    @NotNull
    public final RemoteTerm copy(long j, long j2, int i, @NotNull String word, String str, @InterfaceC4853h(name = "_imageUrl") String str2, @InterfaceC4853h(name = "clientId") Long l, @JsonString String str3, @JsonString String str4, @InterfaceC4853h(name = "_wordAudioUrl") String str5, @InterfaceC4853h(name = "_definitionAudioUrl") String str6) {
        Intrinsics.checkNotNullParameter(word, "word");
        return new RemoteTerm(j, j2, i, word, str, str2, l, str3, str4, str5, str6);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteTerm)) {
            return false;
        }
        RemoteTerm remoteTerm = (RemoteTerm) obj;
        return this.a == remoteTerm.a && this.b == remoteTerm.b && this.c == remoteTerm.c && Intrinsics.b(this.d, remoteTerm.d) && Intrinsics.b(this.e, remoteTerm.e) && Intrinsics.b(this.f, remoteTerm.f) && Intrinsics.b(this.g, remoteTerm.g) && Intrinsics.b(this.h, remoteTerm.h) && Intrinsics.b(this.i, remoteTerm.i) && Intrinsics.b(this.j, remoteTerm.j) && Intrinsics.b(this.k, remoteTerm.k);
    }

    public final int hashCode() {
        int iE = d0.e(d0.b(this.c, d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31), 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Long l = this.g;
        int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
        String str3 = this.h;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.i;
        int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.j;
        int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.k;
        return iHashCode6 + (str6 != null ? str6.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteTerm(id=");
        sb.append(this.a);
        sb.append(", setId=");
        sb.append(this.b);
        sb.append(", rank=");
        sb.append(this.c);
        sb.append(", word=");
        sb.append(this.d);
        sb.append(", definition=");
        sb.append(this.e);
        sb.append(", imageUrl=");
        sb.append(this.f);
        sb.append(", localId=");
        sb.append(this.g);
        sb.append(", wordRichText=");
        sb.append(this.h);
        sb.append(", definitionRichText=");
        sb.append(this.i);
        sb.append(", wordAudioUrl=");
        sb.append(this.j);
        sb.append(", definitionAudioUrl=");
        return android.support.v4.media.session.a.t(sb, this.k, ")");
    }

    /*  JADX ERROR: NullPointerException in pass: InitCodeVariables
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.SSAVar.getPhiList()" because "resultVar" is null
        	at jadx.core.dex.visitors.InitCodeVariables.collectConnectedVars(InitCodeVariables.java:119)
        	at jadx.core.dex.visitors.InitCodeVariables.setCodeVar(InitCodeVariables.java:82)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVar(InitCodeVariables.java:74)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVars(InitCodeVariables.java:48)
        	at jadx.core.dex.visitors.InitCodeVariables.visit(InitCodeVariables.java:29)
        */
    public /* synthetic */ RemoteTerm(long r17, long r19, int r21, java.lang.String r22, java.lang.String r23, java.lang.String r24, java.lang.Long r25, java.lang.String r26, java.lang.String r27, java.lang.String r28, java.lang.String r29, int r30, kotlin.jvm.internal.DefaultConstructorMarker r31) {
        /*
            r16 = this;
            r0 = r30
            r1 = r0 & 8
            if (r1 == 0) goto La
            java.lang.String r1 = ""
            r8 = r1
            goto Lc
        La:
            r8 = r22
        Lc:
            r1 = r0 & 128(0x80, float:1.8E-43)
            r2 = 0
            if (r1 == 0) goto L13
            r12 = r2
            goto L15
        L13:
            r12 = r26
        L15:
            r0 = r0 & 256(0x100, float:3.59E-43)
            if (r0 == 0) goto L2d
            r13 = r2
            r3 = r17
            r5 = r19
            r7 = r21
            r9 = r23
            r10 = r24
            r11 = r25
            r14 = r28
            r15 = r29
            r2 = r16
            goto L41
        L2d:
            r13 = r27
            r2 = r16
            r3 = r17
            r5 = r19
            r7 = r21
            r9 = r23
            r10 = r24
            r11 = r25
            r14 = r28
            r15 = r29
        L41:
            r2.<init>(r3, r5, r7, r8, r9, r10, r11, r12, r13, r14, r15)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.term.RemoteTerm.<init>(long, long, int, java.lang.String, java.lang.String, java.lang.String, java.lang.Long, java.lang.String, java.lang.String, java.lang.String, java.lang.String, int, kotlin.jvm.internal.DefaultConstructorMarker):void");
    }
}
