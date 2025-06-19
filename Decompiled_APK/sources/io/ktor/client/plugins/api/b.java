package io.ktor.client.plugins.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlinx.serialization.json.s;
import kotlinx.serialization.json.u;
import kotlinx.serialization.json.x;
import kotlinx.serialization.json.z;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Unit.a;
            case 1:
                return Unit.a;
            case 2:
                return Unit.a;
            case 3:
                return new LinkedHashMap();
            case 4:
                return new ArrayList();
            case 5:
                return new ArrayList();
            case 6:
                return Unit.a;
            case 7:
                return z.b;
            case 8:
                return u.b;
            case 9:
                return s.b;
            case 10:
                return x.b;
            default:
                return kotlinx.serialization.json.f.b;
        }
    }
}
