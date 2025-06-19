package com.quizlet.assembly.compose.menu;

import com.comscore.streaming.EventType;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.koin.core.error.DefinitionOverrideException;

/* loaded from: classes2.dex */
public final class e extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(List list, int i) {
        super(1);
        this.a = i;
        this.b = list;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws DefinitionOverrideException {
        List modules = this.b;
        switch (this.a) {
            case 0:
                modules.get(((Number) obj).intValue());
                return null;
            case 1:
                modules.get(((Number) obj).intValue());
                return null;
            case 2:
                modules.get(((Number) obj).intValue());
                return null;
            case 3:
                modules.get(((Number) obj).intValue());
                return null;
            case 4:
                modules.get(((Number) obj).intValue());
                return null;
            case 5:
                modules.get(((Number) obj).intValue());
                return null;
            case 6:
                modules.get(((Number) obj).intValue());
                return null;
            case 7:
                modules.get(((Number) obj).intValue());
                return null;
            case 8:
                modules.get(((Number) obj).intValue());
                return null;
            case 9:
                modules.get(((Number) obj).intValue());
                return null;
            case 10:
                modules.get(((Number) obj).intValue());
                return null;
            case 11:
                modules.get(((Number) obj).intValue());
                return null;
            case 12:
                modules.get(((Number) obj).intValue());
                return null;
            case 13:
                modules.get(((Number) obj).intValue());
                return null;
            case 14:
                modules.get(((Number) obj).intValue());
                return null;
            case 15:
                modules.get(((Number) obj).intValue());
                return null;
            case 16:
                modules.get(((Number) obj).intValue());
                return null;
            case 17:
                modules.get(((Number) obj).intValue());
                return null;
            case 18:
                modules.get(((Number) obj).intValue());
                return null;
            case 19:
                modules.get(((Number) obj).intValue());
                return null;
            case 20:
                modules.get(((Number) obj).intValue());
                return null;
            case 21:
                modules.get(((Number) obj).intValue());
                return null;
            case EventType.WINDOW_STATE /* 22 */:
                modules.get(((Number) obj).intValue());
                return null;
            case EventType.AUDIO /* 23 */:
                modules.get(((Number) obj).intValue());
                return Long.MIN_VALUE;
            case EventType.VIDEO /* 24 */:
                modules.get(((Number) obj).intValue());
                return Long.MIN_VALUE;
            case EventType.SUBS /* 25 */:
                modules.get(((Number) obj).intValue());
                return null;
            default:
                org.koin.core.a startKoin = (org.koin.core.a) obj;
                Intrinsics.checkNotNullParameter(startKoin, "$this$startKoin");
                startKoin.b = true;
                Intrinsics.checkNotNullParameter(modules, "modules");
                com.quizlet.data.repository.login.a aVar = startKoin.a;
                com.quizlet.quizletandroid.ui.joincontenttofolder.j jVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.j) aVar.c;
                org.koin.core.logger.a aVar2 = org.koin.core.logger.a.b;
                if (jVar.f(aVar2)) {
                    long jNanoTime = System.nanoTime();
                    aVar.k(modules, startKoin.b);
                    Unit unit = Unit.a;
                    int size = ((ConcurrentHashMap) ((com.quizlet.data.repository.user.a) aVar.b).c).size();
                    ((com.quizlet.quizletandroid.ui.joincontenttofolder.j) aVar.c).getClass();
                    com.quizlet.quizletandroid.ui.joincontenttofolder.j.b(aVar2, "Started " + size + " definitions in " + ((System.nanoTime() - jNanoTime) / 1000000.0d) + " ms");
                } else {
                    aVar.k(modules, startKoin.b);
                }
                return Unit.a;
        }
    }
}
