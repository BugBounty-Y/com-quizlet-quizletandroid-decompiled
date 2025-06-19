package androidx.compose.runtime;

import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.runtime.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0797g0 extends kotlin.coroutines.jvm.internal.c {
    public C0799h0 j;
    public Function1 k;
    public /* synthetic */ Object l;
    public final /* synthetic */ C0799h0 m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0797g0(C0799h0 c0799h0, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c0799h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.P(null, this);
    }
}
