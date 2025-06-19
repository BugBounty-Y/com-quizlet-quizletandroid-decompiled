package com.quizlet.remote.model.explanations.textbook;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.explanations.search.b;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteTextbook implements b {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final Boolean h;
    public final Boolean i;
    public final String j;
    public final Long k;
    public final int l;
    public final List m;
    public final boolean n;

    public RemoteTextbook(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "isbn") @NotNull String isbn, @InterfaceC4853h(name = "title") String str, @InterfaceC4853h(name = "authors") String str2, @InterfaceC4853h(name = "imageUrl") String str3, @InterfaceC4853h(name = "imageThumbnailUrl") String str4, @InterfaceC4853h(name = "edition") String str5, @InterfaceC4853h(name = "isPremium") Boolean bool, @InterfaceC4853h(name = "_hasSolutions") Boolean bool2, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "verifiedSolutionCount") int i, @InterfaceC4853h(name = "tableOfContents") List<? extends com.quizlet.remote.model.explanations.toc.a> list, @InterfaceC4853h(name = "isDeleted") boolean z) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        this.a = j;
        this.b = isbn;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = bool;
        this.i = bool2;
        this.j = str6;
        this.k = l;
        this.l = i;
        this.m = list;
        this.n = z;
    }

    @NotNull
    public final RemoteTextbook copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "isbn") @NotNull String isbn, @InterfaceC4853h(name = "title") String str, @InterfaceC4853h(name = "authors") String str2, @InterfaceC4853h(name = "imageUrl") String str3, @InterfaceC4853h(name = "imageThumbnailUrl") String str4, @InterfaceC4853h(name = "edition") String str5, @InterfaceC4853h(name = "isPremium") Boolean bool, @InterfaceC4853h(name = "_hasSolutions") Boolean bool2, @InterfaceC4853h(name = "_webUrl") String str6, @InterfaceC4853h(name = "timestamp") Long l, @InterfaceC4853h(name = "verifiedSolutionCount") int i, @InterfaceC4853h(name = "tableOfContents") List<? extends com.quizlet.remote.model.explanations.toc.a> list, @InterfaceC4853h(name = "isDeleted") boolean z) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        return new RemoteTextbook(j, isbn, str, str2, str3, str4, str5, bool, bool2, str6, l, i, list, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteTextbook)) {
            return false;
        }
        RemoteTextbook remoteTextbook = (RemoteTextbook) obj;
        return this.a == remoteTextbook.a && Intrinsics.b(this.b, remoteTextbook.b) && Intrinsics.b(this.c, remoteTextbook.c) && Intrinsics.b(this.d, remoteTextbook.d) && Intrinsics.b(this.e, remoteTextbook.e) && Intrinsics.b(this.f, remoteTextbook.f) && Intrinsics.b(this.g, remoteTextbook.g) && Intrinsics.b(this.h, remoteTextbook.h) && Intrinsics.b(this.i, remoteTextbook.i) && Intrinsics.b(this.j, remoteTextbook.j) && Intrinsics.b(this.k, remoteTextbook.k) && this.l == remoteTextbook.l && Intrinsics.b(this.m, remoteTextbook.m) && this.n == remoteTextbook.n;
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.f;
        int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.g;
        int iHashCode5 = (iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool = this.h;
        int iHashCode6 = (iHashCode5 + (bool == null ? 0 : bool.hashCode())) * 31;
        Boolean bool2 = this.i;
        int iHashCode7 = (iHashCode6 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str6 = this.j;
        int iHashCode8 = (iHashCode7 + (str6 == null ? 0 : str6.hashCode())) * 31;
        Long l = this.k;
        int iB = d0.b(this.l, (iHashCode8 + (l == null ? 0 : l.hashCode())) * 31, 31);
        List list = this.m;
        return Boolean.hashCode(this.n) + ((iB + (list != null ? list.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteTextbook(id=");
        sb.append(this.a);
        sb.append(", isbn=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", authors=");
        sb.append(this.d);
        sb.append(", imageUrl=");
        sb.append(this.e);
        sb.append(", imageThumbnailUrl=");
        sb.append(this.f);
        sb.append(", edition=");
        sb.append(this.g);
        sb.append(", isPremium=");
        sb.append(this.h);
        sb.append(", hasSolutions=");
        sb.append(this.i);
        sb.append(", webUrl=");
        sb.append(this.j);
        sb.append(", timestampSec=");
        sb.append(this.k);
        sb.append(", verifiedSolutionCount=");
        sb.append(this.l);
        sb.append(", tableOfContentItems=");
        sb.append(this.m);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.n);
    }

    /*  JADX ERROR: NullPointerException in pass: InitCodeVariables
        java.lang.NullPointerException: Cannot invoke "jadx.core.dex.instructions.args.SSAVar.getPhiList()" because "resultVar" is null
        	at jadx.core.dex.visitors.InitCodeVariables.collectConnectedVars(InitCodeVariables.java:119)
        	at jadx.core.dex.visitors.InitCodeVariables.setCodeVar(InitCodeVariables.java:82)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVar(InitCodeVariables.java:74)
        	at jadx.core.dex.visitors.InitCodeVariables.initCodeVars(InitCodeVariables.java:48)
        	at jadx.core.dex.visitors.InitCodeVariables.visit(InitCodeVariables.java:29)
        */
    public /* synthetic */ RemoteTextbook(long r19, java.lang.String r21, java.lang.String r22, java.lang.String r23, java.lang.String r24, java.lang.String r25, java.lang.String r26, java.lang.Boolean r27, java.lang.Boolean r28, java.lang.String r29, java.lang.Long r30, int r31, java.util.List r32, boolean r33, int r34, kotlin.jvm.internal.DefaultConstructorMarker r35) {
        /*
            r18 = this;
            r0 = r34
            r1 = r0 & 1024(0x400, float:1.435E-42)
            if (r1 == 0) goto L9
            r1 = 0
            r14 = r1
            goto Lb
        L9:
            r14 = r30
        Lb:
            r1 = r0 & 2048(0x800, float:2.87E-42)
            r2 = 0
            if (r1 == 0) goto L12
            r15 = r2
            goto L14
        L12:
            r15 = r31
        L14:
            r0 = r0 & 8192(0x2000, float:1.148E-41)
            if (r0 == 0) goto L33
            r17 = r2
            r3 = r19
            r5 = r21
            r6 = r22
            r7 = r23
            r8 = r24
            r9 = r25
            r10 = r26
            r11 = r27
            r12 = r28
            r13 = r29
            r16 = r32
            r2 = r18
            goto L4d
        L33:
            r17 = r33
            r2 = r18
            r3 = r19
            r5 = r21
            r6 = r22
            r7 = r23
            r8 = r24
            r9 = r25
            r10 = r26
            r11 = r27
            r12 = r28
            r13 = r29
            r16 = r32
        L4d:
            r2.<init>(r3, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.explanations.textbook.RemoteTextbook.<init>(long, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.Boolean, java.lang.Boolean, java.lang.String, java.lang.Long, int, java.util.List, boolean, int, kotlin.jvm.internal.DefaultConstructorMarker):void");
    }
}
