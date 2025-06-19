package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import kotlin.C4937f;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;

/* loaded from: classes2.dex */
public abstract class J {
    public static final void a(int i, InterfaceC0806l interfaceC0806l, androidx.compose.ui.q qVar, Function0 onClearValueAction) {
        Function0 function0;
        Intrinsics.checkNotNullParameter(onClearValueAction, "onClearValueAction");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-109388548);
        int i2 = (c0814p.h(onClearValueAction) ? 4 : 2) | i | 48;
        if ((i2 & 19) == 18 && c0814p.x()) {
            c0814p.Q();
            function0 = onClearValueAction;
        } else {
            qVar = androidx.compose.ui.n.b;
            function0 = onClearValueAction;
            androidx.compose.material3.Z1.h(function0, androidx.compose.ui.platform.N.G(qVar, "clearFieldButton"), false, null, com.quizlet.login.common.ui.i.a, c0814p, (i2 & 14) | 196608, 28);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.b(function0, qVar, i, 5);
        }
    }

    public static final com.mayakapps.kache.journal.a b(okio.t tVar, okio.x directory, int i, com.mayakapps.kache.x strategy) {
        Intrinsics.checkNotNullParameter(tVar, "<this>");
        Intrinsics.checkNotNullParameter(directory, "directory");
        Intrinsics.checkNotNullParameter(strategy, "strategy");
        okio.x xVarF = okio.x.f(directory, "journal");
        okio.x xVarF2 = okio.x.f(directory, "journal.tmp");
        okio.x xVarF3 = okio.x.f(directory, "journal.bkp");
        if (tVar.p(xVarF3)) {
            if (tVar.p(xVarF)) {
                tVar.j(xVarF3);
            } else {
                tVar.d(xVarF3, xVarF);
            }
        }
        tVar.j(xVarF2);
        Throwable th = null;
        if (!tVar.p(xVarF)) {
            return null;
        }
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        com.mayakapps.kache.journal.i iVar = new com.mayakapps.kache.journal.i(AbstractC5085b.c(tVar.P(xVarF)), i, strategy);
        int i2 = 0;
        try {
            iVar.d();
            while (true) {
                com.mayakapps.kache.journal.h hVarA = iVar.a();
                if (hVarA == null) {
                    break;
                }
                i2++;
                if (hVarA instanceof com.mayakapps.kache.journal.e) {
                    linkedHashSet.add(hVarA.getKey());
                } else if (hVarA instanceof com.mayakapps.kache.journal.c) {
                    String str = (String) linkedHashMap.remove(hVarA.getKey());
                    linkedHashSet.remove(hVarA.getKey());
                    linkedHashMap.put(hVarA.getKey(), str);
                } else if (hVarA instanceof com.mayakapps.kache.journal.d) {
                    linkedHashMap.remove(hVarA.getKey());
                    linkedHashSet.remove(hVarA.getKey());
                    linkedHashMap.put(hVarA.getKey(), ((com.mayakapps.kache.journal.d) hVarA).b);
                } else if (hVarA instanceof com.mayakapps.kache.journal.b) {
                    linkedHashSet.remove(hVarA.getKey());
                } else if (hVarA instanceof com.mayakapps.kache.journal.g) {
                    linkedHashSet.remove(hVarA.getKey());
                    linkedHashMap.remove(hVarA.getKey());
                } else if ((hVarA instanceof com.mayakapps.kache.journal.f) && (strategy == com.mayakapps.kache.x.a || strategy == com.mayakapps.kache.x.b)) {
                    linkedHashMap.put(hVarA.getKey(), (String) linkedHashMap.remove(hVarA.getKey()));
                }
            }
            Unit unit = Unit.a;
            try {
                iVar.close();
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (Throwable th3) {
            th = th3;
            try {
                iVar.close();
            } catch (Throwable th4) {
                C4937f.a(th, th4);
            }
        }
        if (th == null) {
            return new com.mayakapps.kache.journal.a(linkedHashMap, linkedHashSet, i2 - linkedHashMap.size());
        }
        throw th;
    }

    public static final void c(okio.n nVar, okio.x directory, Map cleanEntries, Collection dirtyEntryKeys) {
        Intrinsics.checkNotNullParameter(nVar, "<this>");
        Intrinsics.checkNotNullParameter(directory, "directory");
        Intrinsics.checkNotNullParameter(cleanEntries, "cleanEntries");
        Intrinsics.checkNotNullParameter(dirtyEntryKeys, "dirtyEntryKeys");
        okio.x source = okio.x.f(directory, "journal");
        okio.x xVarF = okio.x.f(directory, "journal.tmp");
        okio.x target = okio.x.f(directory, "journal.bkp");
        nVar.j(xVarF);
        com.mayakapps.kache.journal.i iVar = new com.mayakapps.kache.journal.i(AbstractC5085b.b(nVar.D(xVarF, true)));
        try {
            okio.z zVar = (okio.z) iVar.d;
            zVar.H("JOURNAL");
            zVar.v(4);
            zVar.d(iVar.b);
            zVar.v(iVar.c.ordinal());
            zVar.flush();
            iVar.f(cleanEntries, dirtyEntryKeys);
            Unit unit = Unit.a;
            try {
                iVar.close();
                th = null;
            } catch (Throwable th) {
                th = th;
            }
        } catch (Throwable th2) {
            th = th2;
            try {
                iVar.close();
            } catch (Throwable th3) {
                C4937f.a(th, th3);
            }
        }
        if (th != null) {
            throw th;
        }
        if (nVar.p(source)) {
            Intrinsics.checkNotNullParameter(nVar, "<this>");
            Intrinsics.checkNotNullParameter(source, "source");
            Intrinsics.checkNotNullParameter(target, "target");
            nVar.j(target);
            nVar.d(source, target);
        }
        nVar.d(xVarF, source);
        nVar.j(target);
    }
}
