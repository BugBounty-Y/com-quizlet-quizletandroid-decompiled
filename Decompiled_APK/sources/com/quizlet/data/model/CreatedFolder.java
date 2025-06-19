package com.quizlet.data.model;

import com.squareup.moshi.InterfaceC4853h;
import kotlin.Metadata;

@Metadata
/* loaded from: classes2.dex */
public abstract class CreatedFolder extends AbstractC4119d0 {
    public final long a;
    public final boolean b;
    public final long c;
    public final long d;
    public final boolean e;
    public final long f;
    public final String g;
    public final long h;
    public final boolean i;
    public final String j;
    public final Long k;

    public /* synthetic */ CreatedFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, String str, String str2, long j5, boolean z3, String str3, Long l, String str4, int i) {
        this(j, z, j2, j3, z2, j4, str, str2, j5, z3, str3, l, str4);
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public long a() {
        return this.a;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public long b() {
        return this.c;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public long c() {
        return this.d;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public boolean d() {
        return this.b;
    }

    @Override // com.quizlet.data.model.AbstractC4119d0
    public boolean e() {
        return this.e;
    }

    public Long f() {
        return this.k;
    }

    public String g() {
        return this.g;
    }

    public long h() {
        return this.f;
    }

    public long i() {
        return this.h;
    }

    public String j() {
        return this.j;
    }

    public boolean k() {
        return this.i;
    }

    private CreatedFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, String str, String str2, long j5, boolean z3, String str3, Long l, @InterfaceC4853h(name = "folderTypeLabel") String str4) {
        this.a = j;
        this.b = z;
        this.c = j2;
        this.d = j3;
        this.e = z2;
        this.f = j4;
        this.g = str;
        this.h = j5;
        this.i = z3;
        this.j = str3;
        this.k = l;
    }
}
