package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.os.RemoteException;
import android.support.v4.media.session.a;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.common.internal.u;
import com.quizlet.db.data.models.persisted.fields.DBProgressResetFields;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class zzhv {
    private final Context zza;
    private final String zzb;
    private final zzpy zzc;
    private final com.google.android.gms.tagmanager.zzck zzd;
    private final com.google.android.gms.tagmanager.zzcb zze;
    private final zzhx zzf;
    private final zzqw zzg;
    private final zzqw zzh;
    private final Set zzi;
    private int zzj;
    private zznm zzk;
    private zzgt zzl;
    private final zzht zzm;

    public zzhv(Context context, String str, zzpy zzpyVar, zzqh zzqhVar, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar) {
        zzhx zzhxVar = new zzhx();
        this.zzf = zzhxVar;
        zzqw zzqwVar = new zzqw(new HashMap(50));
        this.zzg = zzqwVar;
        zzqw zzqwVar2 = new zzqw(new HashMap(10));
        this.zzh = zzqwVar2;
        this.zzi = new HashSet();
        zzhq zzhqVar = new zzhq(this);
        this.zzm = zzhqVar;
        u.i(zzpyVar, "Internal Error: Container resource cannot be null");
        u.i(zzqhVar, "Internal Error: Runtime resource cannot be null");
        u.f(str, "Internal Error: ContainerId cannot be empty");
        u.h(zzckVar);
        u.h(zzcbVar);
        this.zza = context;
        this.zzb = str;
        this.zzc = zzpyVar;
        this.zzd = zzckVar;
        this.zze = zzcbVar;
        zzhxVar.zzc("1", new zzqr(new zzkl()));
        zzhxVar.zzc("12", new zzqr(new zzkm()));
        zzhxVar.zzc("18", new zzqr(new zzkn()));
        zzhxVar.zzc("19", new zzqr(new zzko()));
        zzhxVar.zzc("20", new zzqr(new zzkp()));
        zzhxVar.zzc("21", new zzqr(new zzkq()));
        zzhxVar.zzc("23", new zzqr(new zzkr()));
        zzhxVar.zzc("24", new zzqr(new zzks()));
        zzhxVar.zzc("27", new zzqr(new zzkt()));
        zzhxVar.zzc("28", new zzqr(new zzku()));
        zzhxVar.zzc("29", new zzqr(new zzkv()));
        zzhxVar.zzc("30", new zzqr(new zzkw()));
        zzhxVar.zzc("32", new zzqr(new zzkx()));
        zzhxVar.zzc("33", new zzqr(new zzkx()));
        zzhxVar.zzc("34", new zzqr(new zzky()));
        zzhxVar.zzc("35", new zzqr(new zzky()));
        zzhxVar.zzc("39", new zzqr(new zzkz()));
        zzhxVar.zzc("40", new zzqr(new zzla()));
        zzhxVar.zzc("0", new zzqr(new zzlx()));
        zzhxVar.zzc("10", new zzqr(new zzly()));
        zzhxVar.zzc("25", new zzqr(new zzlz()));
        zzhxVar.zzc("26", new zzqr(new zzma()));
        zzhxVar.zzc("37", new zzqr(new zzmb()));
        zzhxVar.zzc("2", new zzqr(new zzlb()));
        zzhxVar.zzc("3", new zzqr(new zzlc()));
        zzhxVar.zzc("4", new zzqr(new zzld()));
        zzhxVar.zzc("5", new zzqr(new zzle()));
        zzhxVar.zzc("6", new zzqr(new zzlf()));
        zzhxVar.zzc("7", new zzqr(new zzlg()));
        zzhxVar.zzc("8", new zzqr(new zzlh()));
        zzhxVar.zzc("9", new zzqr(new zzle()));
        zzhxVar.zzc("13", new zzqr(new zzli()));
        zzhxVar.zzc("47", new zzqr(new zzlj()));
        zzhxVar.zzc("15", new zzqr(new zzlk()));
        zzhxVar.zzc("48", new zzqr(new zzll(this)));
        zzlm zzlmVar = new zzlm();
        zzhxVar.zzc("16", new zzqr(zzlmVar));
        zzhxVar.zzc("17", new zzqr(zzlmVar));
        zzhxVar.zzc("22", new zzqr(new zzlo()));
        zzhxVar.zzc("45", new zzqr(new zzlp()));
        zzhxVar.zzc("46", new zzqr(new zzlq()));
        zzhxVar.zzc("36", new zzqr(new zzlr()));
        zzhxVar.zzc("43", new zzqr(new zzls()));
        zzhxVar.zzc("38", new zzqr(new zzlt()));
        zzhxVar.zzc("44", new zzqr(new zzlu()));
        zzhxVar.zzc("41", new zzqr(new zzlv()));
        zzhxVar.zzc("42", new zzqr(new zzlw()));
        zzl(zza.CONTAINS, new zzoj());
        zzl(zza.ENDS_WITH, new zzok());
        zzl(zza.EQUALS, new zzol());
        zzl(zza.GREATER_EQUALS, new zzom());
        zzl(zza.GREATER_THAN, new zzon());
        zzl(zza.LESS_EQUALS, new zzoo());
        zzl(zza.LESS_THAN, new zzop());
        zzl(zza.REGEX, new zzor());
        zzl(zza.STARTS_WITH, new zzos());
        zzqwVar.zzf("advertiserId", new zzqr(new zznc(context)));
        zzqwVar.zzf("advertiserTrackingEnabled", new zzqr(new zznd(context)));
        zzqwVar.zzf("adwordsClickReferrer", new zzqr(new zzne(zzhqVar)));
        zzqwVar.zzf("applicationId", new zzqr(new zznf(context)));
        zzqwVar.zzf("applicationName", new zzqr(new zzng(context)));
        zzqwVar.zzf("applicationVersion", new zzqr(new zznh(context)));
        zzqwVar.zzf("applicationVersionName", new zzqr(new zzni(context)));
        zzqwVar.zzf("arbitraryPixieMacro", new zzqr(new zzmz(1, zzhxVar)));
        zzqwVar.zzf("carrier", new zzqr(new zznj(context)));
        zzqwVar.zzf("constant", new zzqr(new zzlr()));
        zzqwVar.zzf(DBProgressResetFields.Names.CONTAINER_ID, new zzqr(new zznk(new zzqz(str))));
        zzqwVar.zzf("containerVersion", new zzqr(new zznk(new zzqz(zzpyVar.zzb()))));
        zzhu zzhuVar = null;
        zzqwVar.zzf("customMacro", new zzqr(new zzmy(new zzhs(this, zzhuVar))));
        zzqwVar.zzf("deviceBrand", new zzqr(new zznn()));
        zzqwVar.zzf("deviceId", new zzqr(new zzno(context)));
        zzqwVar.zzf("deviceModel", new zzqr(new zznp()));
        zzqwVar.zzf("deviceName", new zzqr(new zznq()));
        zzqwVar.zzf("encode", new zzqr(new zznr()));
        zzqwVar.zzf("encrypt", new zzqr(new zzns()));
        zzqwVar.zzf("event", new zzqr(new zznl()));
        zzqwVar.zzf("eventParameters", new zzqr(new zznt(zzhqVar)));
        zzqwVar.zzf("version", new zzqr(new zznu()));
        zzqwVar.zzf("hashcode", new zzqr(new zznv()));
        zzqwVar.zzf("installReferrer", new zzqr(new zznw(context)));
        zzqwVar.zzf("join", new zzqr(new zznx()));
        zzqwVar.zzf("language", new zzqr(new zzny()));
        zzqwVar.zzf("locale", new zzqr(new zznz()));
        zzqwVar.zzf("adWordsUniqueId", new zzqr(new zzob(context)));
        zzqwVar.zzf(DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY, new zzqr(new zzoc()));
        zzqwVar.zzf("platform", new zzqr(new zzod()));
        zzqwVar.zzf("random", new zzqr(new zzoe()));
        zzqwVar.zzf("regexGroup", new zzqr(new zzof()));
        zzqwVar.zzf("resolution", new zzqr(new zzoh(context)));
        zzqwVar.zzf("runtimeVersion", new zzqr(new zzog()));
        zzqwVar.zzf("sdkVersion", new zzqr(new zzoi()));
        this.zzk = new zznm();
        zzqwVar.zzf("currentTime", new zzqr(this.zzk));
        zzqwVar.zzf("userProperty", new zzqr(new zzoa(zzhqVar)));
        zzqwVar.zzf("arbitraryPixel", new zzqr(new zzov(zzgr.zza(context))));
        zzqwVar.zzf("customTag", new zzqr(new zzmy(new zzhr(this, zzhuVar))));
        zzqwVar.zzf("universalAnalytics", new zzqr(new zzow(context, zzhqVar)));
        zzqwVar.zzf("queueRequest", new zzqr(new zzot(zzgr.zza(context))));
        zzqwVar.zzf("sendMeasurement", new zzqr(new zzou(zzckVar, zzhqVar)));
        zzqwVar.zzf("arbitraryPixieTag", new zzqr(new zzmz(0, zzhxVar)));
        zzqwVar.zzf("suppressPassthrough", new zzqr(new zznb(context, zzhqVar)));
        zzqwVar2.zzf("decodeURI", new zzqr(new zzms()));
        zzqwVar2.zzf("decodeURIComponent", new zzqr(new zzmt()));
        zzqwVar2.zzf("encodeURI", new zzqr(new zzmu()));
        zzqwVar2.zzf("encodeURIComponent", new zzqr(new zzmv()));
        zzqwVar2.zzf("log", new zzqr(new zzna()));
        zzqwVar2.zzf("isArray", new zzqr(new zzmw()));
        for (zzjl zzjlVar : zzqhVar.zza()) {
            zzjlVar.zzc(this.zzf);
            this.zzf.zzc(zzjlVar.zzb(), new zzqr(zzjlVar));
        }
        zzqw zzqwVar3 = new zzqw(new HashMap(1));
        zzqwVar3.zzf(DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY, this.zzg);
        zzqwVar3.zzf("common", this.zzh);
        this.zzf.zzc("gtmUtils", zzqwVar3);
        zzqw zzqwVar4 = new zzqw(new HashMap(this.zzg.zzi()));
        zzqwVar4.zzj();
        zzqw zzqwVar5 = new zzqw(new HashMap(this.zzh.zzi()));
        zzqwVar5.zzj();
        if (this.zzf.zzf("main") && (this.zzf.zzb("main") instanceof zzqr)) {
            ArrayList arrayList = new ArrayList();
            arrayList.add(zzqwVar3);
            zzra.zzd(this.zzf, new zzqx("main", arrayList));
        }
        this.zzg.zzf("base", zzqwVar4);
        this.zzh.zzf("base", zzqwVar5);
        zzqwVar3.zzj();
        this.zzg.zzj();
        this.zzh.zzj();
    }

    private final zzqo zzg(Map map) {
        zzqx zzqxVarZza;
        zzqo zzqoVar = (zzqo) map.get(zzb.FUNCTION.toString());
        if (!(zzqoVar instanceof zzqz)) {
            zzgp.zza("No function id in properties", this.zza);
            return zzqs.zze;
        }
        String strZzk = ((zzqz) zzqoVar).zzk();
        if (this.zzf.zzf(strZzk)) {
            HashMap map2 = new HashMap();
            for (Map.Entry entry : map.entrySet()) {
                if (((String) entry.getKey()).startsWith("vtp_")) {
                    map2.put(((String) entry.getKey()).substring(4), (zzqo) entry.getValue());
                }
            }
            ArrayList arrayList = new ArrayList();
            arrayList.add(new zzqw(map2));
            zzqxVarZza = new zzqx(strZzk, arrayList);
        } else {
            String strZzb = zzjk.zzb(strZzk);
            if (strZzb == null || !this.zzg.zzh(strZzb)) {
                zzgp.zza(a.B("functionId '", strZzk, "' is not supported"), this.zza);
                return zzqs.zze;
            }
            try {
                zzqxVarZza = zzjk.zza(strZzk, map, this.zzf);
            } catch (RuntimeException e) {
                zzhi.zza("Incorrect keys for function " + strZzk + ". " + e.getMessage());
                zzqxVarZza = null;
            }
        }
        if (zzqxVarZza == null) {
            zzgp.zza("Internal error: failed to convert function to a valid statement", this.zza);
            return zzqs.zze;
        }
        zzhi.zzd("Executing: ".concat(String.valueOf(zzqxVarZza.zzi())));
        zzqo zzqoVarZzd = zzra.zzd(this.zzf, zzqxVarZza);
        if (!(zzqoVarZzd instanceof zzqs)) {
            return zzqoVarZzd;
        }
        zzqs zzqsVar = (zzqs) zzqoVarZzd;
        return zzqsVar.zzj() ? zzqsVar.zzi() : zzqoVarZzd;
    }

    private final zzqo zzh(zzqk zzqkVar) {
        switch (zzqkVar.zza()) {
            case 1:
                try {
                    return new zzqq(Double.valueOf(Double.parseDouble((String) zzqkVar.zzb())));
                } catch (NumberFormatException unused) {
                    return new zzqz((String) zzqkVar.zzb());
                }
            case 2:
                List list = (List) zzqkVar.zzb();
                ArrayList arrayList = new ArrayList(list.size());
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(zzh((zzqk) it2.next()));
                }
                return new zzqv(arrayList);
            case 3:
                Map map = (Map) zzqkVar.zzb();
                HashMap map2 = new HashMap(map.size());
                for (Map.Entry entry : map.entrySet()) {
                    zzqo zzqoVarZzh = zzh((zzqk) entry.getKey());
                    map2.put(zzjn.zzd(zzqoVarZzh), zzh((zzqk) entry.getValue()));
                }
                return new zzqw(map2);
            case 4:
                zzqo zzqoVarZzi = zzi((String) zzqkVar.zzb());
                if (!(zzqoVarZzi instanceof zzqz) || zzqkVar.zzc().isEmpty()) {
                    return zzqoVarZzi;
                }
                String strZzk = ((zzqz) zzqoVarZzi).zzk();
                Iterator it3 = zzqkVar.zzc().iterator();
                while (it3.hasNext()) {
                    if (((Integer) it3.next()).intValue() == 12) {
                        try {
                            strZzk = URLEncoder.encode(strZzk, "UTF-8").replaceAll("\\+", "%20");
                        } catch (UnsupportedEncodingException e) {
                            zzhi.zzb("Escape URI: unsupported encoding", e);
                        }
                    }
                }
                return new zzqz(strZzk);
            case 5:
                return new zzqz((String) zzqkVar.zzb());
            case 6:
                return new zzqq(Double.valueOf(((Integer) zzqkVar.zzb()).doubleValue()));
            case 7:
                StringBuilder sb = new StringBuilder();
                Iterator it4 = ((List) zzqkVar.zzb()).iterator();
                while (it4.hasNext()) {
                    sb.append(zzjn.zzd(zzh((zzqk) it4.next())));
                }
                return new zzqz(sb.toString());
            default:
                return new zzqp((Boolean) zzqkVar.zzb());
        }
    }

    private final zzqo zzi(String str) {
        this.zzj++;
        zzhi.zzd(zzj() + "Beginning to evaluate variable " + str);
        if (this.zzi.contains(str)) {
            this.zzj--;
            throw new IllegalStateException(a.m("Macro cycle detected.  Current macro reference: ", str, ". Previous macro references: ", this.zzi.toString()));
        }
        this.zzi.add(str);
        zzqb zzqbVarZza = this.zzc.zza(str);
        if (zzqbVarZza == null) {
            this.zzj--;
            this.zzi.remove(str);
            throw new IllegalStateException(a.l(zzj(), "Attempting to resolve unknown macro ", str));
        }
        zzqo zzqoVarZzg = zzg(zzk(zzqbVarZza.zza()));
        zzhi.zzd(zzj() + "Done evaluating variable " + str);
        this.zzj = this.zzj + (-1);
        this.zzi.remove(str);
        return zzqoVarZzg;
    }

    private final String zzj() {
        if (this.zzj <= 1) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append(Integer.toString(this.zzj));
        for (int i = 2; i < this.zzj; i++) {
            sb.append(' ');
        }
        sb.append(": ");
        return sb.toString();
    }

    private final Map zzk(Map map) {
        HashMap map2 = new HashMap();
        for (Map.Entry entry : map.entrySet()) {
            map2.put((String) entry.getKey(), zzh((zzqk) entry.getValue()));
        }
        return map2;
    }

    private final void zzl(zza zzaVar, zzjm zzjmVar) {
        int i = zzjk.a;
        this.zzg.zzf(zzjk.zzb(zzaVar.toString()), new zzqr(zzjmVar));
    }

    public final zzqo zzc(String str) {
        if (this.zzi.contains(str)) {
            throw new IllegalStateException(a.m("Macro cycle detected.  Current macro reference: ", str, ". Previous macro references: ", this.zzi.toString()));
        }
        this.zzj = 0;
        return zzi(str);
    }

    public final zzqo zzd(zzqb zzqbVar) {
        this.zzi.clear();
        try {
            zzqo zzqoVarZzg = zzg(zzk(zzqbVar.zza()));
            if (zzqoVarZzg instanceof zzqp) {
                return zzqoVarZzg;
            }
            zzgp.zza("Predicate must return a boolean value", this.zza);
            return new zzqp(Boolean.FALSE);
        } catch (IllegalStateException unused) {
            zzhi.zza("Error evaluating predicate.");
            return zzqs.zzd;
        }
    }

    public final void zze() {
        zzgr.zza(this.zza);
        zzig.zzf().zzi();
    }

    public final void zzf(zzgt zzgtVar) {
        zzqo zzqpVar;
        this.zzf.zzc("gtm.globals.eventName", new zzqz(zzgtVar.zzb()));
        this.zzk.zza(zzgtVar);
        this.zzl = zzgtVar;
        HashSet hashSet = new HashSet();
        HashSet hashSet2 = new HashSet();
        HashMap map = new HashMap();
        for (zzqe zzqeVar : this.zzc.zzc()) {
            if (zzqeVar.zza().isEmpty() && zzqeVar.zzd().isEmpty()) {
                zzhi.zzd("Trigger is not being evaluated since it has no associated tags: ".concat(String.valueOf(zzqeVar)));
            } else {
                zzhi.zzd("Evaluating trigger ".concat(String.valueOf(zzqeVar)));
                Iterator it2 = zzqeVar.zzb().iterator();
                while (true) {
                    if (it2.hasNext()) {
                        zzqb zzqbVar = (zzqb) it2.next();
                        zzqo zzqoVarZzd = (zzqo) map.get(zzqbVar);
                        if (zzqoVarZzd == null) {
                            zzqoVarZzd = zzd(zzqbVar);
                            map.put(zzqbVar, zzqoVarZzd);
                        }
                        zzqpVar = zzqs.zzd;
                        if (zzqoVarZzd != zzqpVar) {
                            if (((zzqp) zzqoVarZzd).zzi().booleanValue()) {
                                zzqpVar = new zzqp(Boolean.FALSE);
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        Iterator it3 = zzqeVar.zzc().iterator();
                        while (true) {
                            if (!it3.hasNext()) {
                                zzqpVar = new zzqp(Boolean.TRUE);
                                break;
                            }
                            zzqb zzqbVar2 = (zzqb) it3.next();
                            zzqo zzqoVarZzd2 = (zzqo) map.get(zzqbVar2);
                            if (zzqoVarZzd2 == null) {
                                zzqoVarZzd2 = zzd(zzqbVar2);
                                map.put(zzqbVar2, zzqoVarZzd2);
                            }
                            zzqpVar = zzqs.zzd;
                            if (zzqoVarZzd2 != zzqpVar) {
                                if (!((zzqp) zzqoVarZzd2).zzi().booleanValue()) {
                                    zzqpVar = new zzqp(Boolean.FALSE);
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                if (zzqpVar == zzqs.zzd) {
                    zzgp.zzc("Error encounted while evaluating trigger ".concat(String.valueOf(zzqeVar)), this.zza);
                    if (!zzqeVar.zzd().isEmpty()) {
                        zzhi.zzd("Blocking tags: ".concat(String.valueOf(zzqeVar.zzd())));
                        hashSet2.addAll(zzqeVar.zzd());
                    }
                } else if (((zzqp) zzqpVar).zzi().booleanValue()) {
                    zzhi.zzd("Trigger is firing: ".concat(String.valueOf(zzqeVar)));
                    if (!zzqeVar.zza().isEmpty()) {
                        zzhi.zzd("Adding tags to firing candidates: ".concat(String.valueOf(zzqeVar.zza())));
                        hashSet.addAll(zzqeVar.zza());
                    }
                    if (!zzqeVar.zzd().isEmpty()) {
                        zzhi.zzd("Blocking disabled tags: ".concat(String.valueOf(zzqeVar.zzd())));
                        hashSet2.addAll(zzqeVar.zzd());
                    }
                }
            }
        }
        hashSet.removeAll(hashSet2);
        Iterator it4 = hashSet.iterator();
        boolean z = false;
        while (it4.hasNext()) {
            zzqb zzqbVar3 = (zzqb) it4.next();
            this.zzi.clear();
            zzhi.zzd("Executing firing tag ".concat(String.valueOf(zzqbVar3)));
            try {
                zzg(zzk(zzqbVar3.zza()));
                zzqk zzqkVar = (zzqk) zzqbVar3.zza().get(zzb.DISPATCH_ON_FIRE.toString());
                if (zzqkVar != null && zzqkVar.zza() == 8 && ((Boolean) zzqkVar.zzb()).booleanValue()) {
                    z = true;
                    zzhi.zzd("Tag configured to dispatch on fire: " + String.valueOf(zzqbVar3));
                }
            } catch (IllegalStateException e) {
                zzgp.zzb(a.B("Error firing tag ", String.valueOf(zzqbVar3), ": "), e, this.zza);
            }
        }
        this.zzf.zzd("gtm.globals.eventName");
        if (zzgtVar.zzf()) {
            zzhi.zzd("Log passthrough event " + zzgtVar.zzb() + " to Firebase.");
            try {
                this.zzd.zzc(zzgtVar.zzc(), zzgtVar.zzb(), zzgtVar.zza(), zzgtVar.currentTimeMillis());
            } catch (RemoteException e2) {
                zzgp.zzb("Error calling measurement proxy: ", e2, this.zza);
            }
        } else {
            zzhi.zzd("Non-passthrough event " + zzgtVar.zzb() + " doesn't get logged to Firebase directly.");
        }
        if (z) {
            zzhi.zzd("Dispatch called for dispatchOnFire tags.");
            zze();
        }
    }
}
