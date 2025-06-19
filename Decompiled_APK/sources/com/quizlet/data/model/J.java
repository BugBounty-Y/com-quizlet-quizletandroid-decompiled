package com.quizlet.data.model;

/* loaded from: classes2.dex */
public abstract class J extends CreatedFolder {
    public final String l;

    public J(long j, boolean z, long j2, long j3, boolean z2, long j4, String str, String str2, long j5, boolean z3, String str3, Long l, String str4) {
        super(j, z, j2, j3, z2, j4, str, str3, j5, z3, str2, l, str4, 0);
        this.l = str3;
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract Long f();

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract String g();

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract long h();

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract long i();

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract String j();

    @Override // com.quizlet.data.model.CreatedFolder
    public abstract boolean k();

    public abstract com.quizlet.generated.enums.M0 l();

    public String m() {
        return this.l;
    }
}
