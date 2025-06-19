package com.iabtcf.decoder;

import com.iabtcf.utils.l;
import com.snowplowanalytics.core.tracker.q;
import java.util.function.Function;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Function {
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ d(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // java.util.function.Function
    public final Object apply(Object obj) {
        switch (this.b) {
            case 0:
                com.iabtcf.utils.a aVar = (com.iabtcf.utils.a) this.c;
                aVar.getClass();
                return Integer.valueOf(aVar.f(((l) obj).b(aVar)));
            default:
                q event = (q) obj;
                com.snowplowanalytics.snowplow.globalcontexts.a aVar2 = (com.snowplowanalytics.snowplow.globalcontexts.a) this.c;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                com.quizlet.quizletandroid.data.management.d dVar = aVar2.a;
                dVar.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                return dVar.a;
        }
    }
}
