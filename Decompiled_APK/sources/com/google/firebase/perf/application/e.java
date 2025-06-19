package com.google.firebase.perf.application;

import androidx.fragment.app.AbstractC1124b0;
import androidx.fragment.app.Fragment;
import com.google.firebase.perf.metrics.Trace;
import com.google.firebase.perf.util.g;
import java.util.HashMap;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class e extends AbstractC1124b0 {
    public static final com.google.firebase.perf.logging.a f = com.google.firebase.perf.logging.a.d();
    public final WeakHashMap a = new WeakHashMap();
    public final assistantMode.utils.studiableMetadata.b b;
    public final com.google.firebase.perf.transport.f c;
    public final c d;
    public final f e;

    public e(assistantMode.utils.studiableMetadata.b bVar, com.google.firebase.perf.transport.f fVar, c cVar, f fVar2) {
        this.b = bVar;
        this.c = fVar;
        this.d = cVar;
        this.e = fVar2;
    }

    @Override // androidx.fragment.app.AbstractC1124b0
    public final void a(Fragment fragment) {
        com.google.firebase.perf.util.d dVar;
        Object[] objArr = {fragment.getClass().getSimpleName()};
        com.google.firebase.perf.logging.a aVar = f;
        aVar.b("FragmentMonitor %s.onFragmentPaused ", objArr);
        WeakHashMap weakHashMap = this.a;
        if (!weakHashMap.containsKey(fragment)) {
            aVar.g("FragmentMonitor: missed a fragment trace from %s", fragment.getClass().getSimpleName());
            return;
        }
        Trace trace = (Trace) weakHashMap.get(fragment);
        weakHashMap.remove(fragment);
        f fVar = this.e;
        boolean z = fVar.d;
        com.google.firebase.perf.logging.a aVar2 = f.e;
        if (z) {
            HashMap map = fVar.c;
            if (map.containsKey(fragment)) {
                com.google.firebase.perf.metrics.c cVar = (com.google.firebase.perf.metrics.c) map.remove(fragment);
                com.google.firebase.perf.util.d dVarA = fVar.a();
                if (dVarA.b()) {
                    com.google.firebase.perf.metrics.c cVar2 = (com.google.firebase.perf.metrics.c) dVarA.a();
                    cVar2.getClass();
                    dVar = new com.google.firebase.perf.util.d(new com.google.firebase.perf.metrics.c(cVar2.a - cVar.a, cVar2.b - cVar.b, cVar2.c - cVar.c));
                } else {
                    aVar2.b("stopFragment(%s): snapshot() failed", fragment.getClass().getSimpleName());
                    dVar = new com.google.firebase.perf.util.d();
                }
            } else {
                aVar2.b("Sub-recording associated with key %s was not started or does not exist", fragment.getClass().getSimpleName());
                dVar = new com.google.firebase.perf.util.d();
            }
        } else {
            aVar2.a();
            dVar = new com.google.firebase.perf.util.d();
        }
        if (!dVar.b()) {
            aVar.g("onFragmentPaused: recorder failed to trace %s", fragment.getClass().getSimpleName());
        } else {
            g.a(trace, (com.google.firebase.perf.metrics.c) dVar.a());
            trace.stop();
        }
    }

    @Override // androidx.fragment.app.AbstractC1124b0
    public final void b(Fragment fragment) {
        f.b("FragmentMonitor %s.onFragmentResumed", fragment.getClass().getSimpleName());
        Trace trace = new Trace("_st_".concat(fragment.getClass().getSimpleName()), this.c, this.b, this.d);
        trace.start();
        trace.putAttribute("Parent_fragment", fragment.getParentFragment() == null ? "No parent" : fragment.getParentFragment().getClass().getSimpleName());
        if (fragment.getActivity() != null) {
            trace.putAttribute("Hosting_activity", fragment.getActivity().getClass().getSimpleName());
        }
        this.a.put(fragment, trace);
        f fVar = this.e;
        boolean z = fVar.d;
        com.google.firebase.perf.logging.a aVar = f.e;
        if (!z) {
            aVar.a();
            return;
        }
        HashMap map = fVar.c;
        if (map.containsKey(fragment)) {
            aVar.b("Cannot start sub-recording because one is already ongoing with the key %s", fragment.getClass().getSimpleName());
            return;
        }
        com.google.firebase.perf.util.d dVarA = fVar.a();
        if (dVarA.b()) {
            map.put(fragment, (com.google.firebase.perf.metrics.c) dVarA.a());
        } else {
            aVar.b("startFragment(%s): snapshot() failed", fragment.getClass().getSimpleName());
        }
    }
}
