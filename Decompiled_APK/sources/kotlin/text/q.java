package kotlin.text;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class q extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ Regex a;
    public final /* synthetic */ String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(Regex regex, String str) {
        super(0);
        this.a = regex;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final MatchResult invoke() {
        return this.a.b(this.b);
    }
}
