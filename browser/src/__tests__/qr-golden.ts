// GENERATED (never hand-edit): the QR renderer's reference matrices.
// The proof for src/qr.ts: rendered with the qrcode package (v1.5.4, byte
// mode, level M, masks 0-7 + the auto selection) at development time and
// pinned here — the id-qr test replays them against the in-repo renderer.
// Regenerate with the same one-liner if the renderer ever deliberately moves.
// Matrices are packed MSB-first, base64url.

export interface QrGoldenEntry {
  payload: string
  masks: Record<string, { size: number; packed: string }>
  auto: { size: number; packed: string }
}

export const QR_GOLDEN: QrGoldenEntry[] = [
  {
    "payload": "otpauth://totp/OIML%20SMART%20Identity:casey@example.org?secret=JBSWY3DPEHPK3PXP&issuer=OIML%20SMART%20Identity&algorithm=SHA1&digits=6&period=30",
    "masks": {
      "0": {
        "size": 49,
        "packed": "_jj2rnS_wVabETHQbp_4urJrt0oeUIQl260BPv_C7BDT0YZRB_qqqqqq_gBZnGt5AKoUQ_3eiWgoAOwMCu-1jtF0IXQy_huWMzf6a5jr4-VktqyOQNZNgf36VnYxv2n7-NED-Eb6_n1oviAEwgDsySmEcS7ko2A1rj0Wdb-e36fe6sgCxAgkPn0vqofyEVH8a7UResJSuY-oVE9REEBGU_p-_Cc-vAxLdJO0Bu7Sq46EZCqYe8KgLwiPkr8wp7MhVnE5QNKTpD6-AOTyuBAKKvqG3nlWCvmRpwFGViN50N7_whUucyIITikak_Xq097hTozROOLi3WPv2vyAfEMYaMd_h1qvVGrwRMDEOXErrev_qf_90HGqKoJy6-7_JW95BJMqubAC_vG22NlNgA"
      },
      "1": {
        "size": 49,
        "packed": "_u2j-yC_wTwxu5vQbqqt7-drt0C0-i6l26BUf6qC7BZ5cSzxB_qqqqqq_gDzNEHTAKNBF-iLksKCqkamoHrg24QhdD6YVLE8mZKvPs2-trfOHAYk6n8Y1KivAyKbFcNRUntWrROvqyhCFIquaKp5nHzRJHuuCcqfBJezIOrLivKMQGKobqKNfyh__9PmsftUQR8bKpcGrNqtfGX7GurEx-8r-XJ_9qbh3jkeo7uH_tvRNoAy0WgKhl3ax-pl8xmL_NuT6ofG8WvrVc5YErqggG_TiywDX7M7Davs_IYshYuql0eE2Yii5IEfxqC_horj5CZ7kkjjiDf6j_mAVukSwkX_sg-qASuwTmpGk9GLoL6-_K-t0tsAgCja6ruqcDotBDmAExqo_qTjjYwYgA"
      },
      "2": {
        "size": 49,
        "packed": "_lt4lpS_wRij8r_QbqcbNIprt1mQaGel26s5_3HC7BQwUb6xB_qqqqqq_gFhfGVBAL53z-U9PgqmOA-CMiGNbV9MwuyRcCN1vQR0U3tl2wNMVSK2o1quD8UZ2E-7h4p1wDI7G8jCHfMKMBjnTDgi8coKSc18AO4NTbMl-4d9UZ84wiuM_Ouo__MfyQvrkWkcZY0SSqHeoWyuNEFpE85Gn-Kd-h__JK_FTHA6NWDqSAC8ggJ79fpDo-sBqly-njkZtf8Bo-pwKgZdjoZ8gPOEEjS-Pfdu6WEyKTml2BD36D1x-vMGkKwwraUZHc0JXebjdm9fAAHiPu_3OfqAcnsb5se_n7mpbKtwV07E2vEbq9M-J8-d1JIkEmH-6mDHxuFBBKvJN4jh_pI44DrDgA"
      },
      "3": {
        "size": 49,
        "packed": "_tt4lpS_wXUVKdPQbpx2glFrt1mQaGel26aPPhxC7BNd8WXRB_qqqqqq_gHXpEj3ALcae_5QpYqmOA-CMgy7tjL6GZe8xvgYC9R0U3tl2wbqjk8AeDXLuR50bpW7h4p1wDKPwKV0xp7mhsOK-uNi8coKSc1qm4O7lt6YbVwQ50RQwiuM_OuqPp6vkmf8MbJ0U1cfSqHeoWyubGzfGKPEa_nw_MS-hK_FTHA6Pi1ck20KXMkWQyEuF-sBqly-n1CvbpK3eDMdnN0wOAZ8gPOEEhmI5prYMhofn-LIbsD36D1x-vagS8GGdskcqxZk6zzjdm9fAAHi5YPh4v8ARKEWUET_v7mpbKtwXCNGAZGrpQh_kR_11JIkEmH-6w1xHYz3BHCkgVOM_pI44DrDgA"
      },
      "4": {
        "size": 49,
        "packed": "_pxk51C_wTstyl3Qbokj1wRrt16MGaCl269IPm2C7BYIsTCRB_qqqqqq_gEQvHkwAIuw0_T6fLJFtjdhvAKDVbzC-h0WbFKyoXNoIrx5qsDCbcE4m7ie7EshO8Cj9k1psfVK3NSz2u8y05bfr7YB__Lpx_WNh_J8iq9S5_a6Te77TBNvctNK_xCf8evkkRjcef0VOubCsKuqDGLnGy3Ev-yl-ZH_1SjZPbcmQnybjxzNQYxDFnR7QdviJGRdESFocuNwZJu3Nneakr6fDstnnBewBRTg0ZC1NUhixGfrmfptizCIqE--lUUZ_kMxvmjjB6hDccbj-fPm_v6AUfUTBUW_sYGq4quQQFLFHfFrr6L_O7_d0qrHnFke6INJ_gLPBNoOK_km_tUkkf3fgA"
      },
      "5": {
        "size": 49,
        "packed": "_m2j-yC_wXgh-p_QbqcbNIprt1Xhr3ul26M5_3HC7BI4cTyxB_qqqqqq_gHjdEXDAIL3z-U9ZxbX_xPz9SGNbV9Mwu6ZUKF9nYKvPs2-trPOXQI0q3quD8UZ2E_KQJYEBy47G8jCHfMCEJrvbLo5nHzRJHu-CM6PRZOl-4d9UZ85BTf9O_fY__MfyQvrsesURQ8aKpcGrNqtPGHrG-7En-Kd-h__I7O0i2xL9WDqSAC8goBz1XhLgl3ax-pl8hmbvd-Dq-pwKgZdjpoNR-_11TS-Pfdu6WM6Cbut-JYshYuql0OEmIyypYUZHc0JXebisXMuxx3iPu_3OfqAUvkTxkW_kg-qASuwT25G0tGbo9M-J8-d045V1X2O6GDHxuFBBCnBFwrp_qTjjYwYgA"
      },
      "6": {
        "size": 49,
        "packed": "_u2j-yC_wXstyl3Qbq4_psNrt0Xhr3ul26odfzjC7BO-cV0xB_qqqqqq_gDvREbPAJ_TX-wZy5bX_xPz9Sip_xZoUK8fSMD7heKvPs2-trDCbcE4m7uKnYw9SgfKQJYEBy4fiYHmj7oECPtpdNu5nHzRJHuyOA2DdVChac5Zw9YZBTf9O_fYf7o_20PvsYqUXW8cKpcGrNqtDGLnGy3Ej-u5-Fb_o7O0i2xL9ynO2kmYEuH1zRnNml3ax-pl8tqXjRyPm6NUuE95HJoNR-_11T2ar75KeyK8Edor4PYshYuql0CIqE--lUUdj4Qtz67isXMuxx3irKfzq_uASpkV3kQ_sg-qASuwX61G4hGbqZo-tY-9145V1X2O6CnjVKhlBEhHD2tv_qTjjYwYgA"
      },
      "7": {
        "size": 49,
        "packed": "_jj2rnS_wQTSNaPQbptq85Zrt0oeUIQl26dIPm2C7BRBkaLRB_qqqqqq_gAQvHkwAJaGC_lM0GgoAOwMCv38qkM9BfCgtz8Eehf6a5jr4-ctkj7HZEbfyNloH1Ixv2n7-NFK3NSz2u969wSWiyRsySmEcS7th_J8iq9UPJsMloNO6sgCxAglPu9vjhf6UXVsYpETesJSuY-odF0ZFNJHW_7s_QO-_AxLdJO0AnybjxzNRQ4KMuYyZwiPkr8wpyFocuNwZPYB7RosSeTyuBAKKujP-usfLn0D7iXUHwN50N7_whdnV7BBarkY2tF4mvrhTozROOLj-fPm_v6AdWcaIcf_h1qvVGrwUFLFHfFrpM9_4N_t1HGqKoJy6Xy2Af0xBLe48JSQ_vG22NlNgA"
      }
    },
    "auto": {
      "size": 49,
      "packed": "_tt4lpS_wXUVKdPQbpx2glFrt1mQaGel26aPPhxC7BNd8WXRB_qqqqqq_gHXpEj3ALcae_5QpYqmOA-CMgy7tjL6GZe8xvgYC9R0U3tl2wbqjk8AeDXLuR50bpW7h4p1wDKPwKV0xp7mhsOK-uNi8coKSc1qm4O7lt6YbVwQ50RQwiuM_OuqPp6vkmf8MbJ0U1cfSqHeoWyubGzfGKPEa_nw_MS-hK_FTHA6Pi1ck20KXMkWQyEuF-sBqly-n1CvbpK3eDMdnN0wOAZ8gPOEEhmI5prYMhofn-LIbsD36D1x-vagS8GGdskcqxZk6zzjdm9fAAHi5YPh4v8ARKEWUET_v7mpbKtwXCNGAZGrpQh_kR_11JIkEmH-6w1xHYz3BHCkgVOM_pI44DrDgA"
    }
  },
  {
    "payload": "HELLO WORLD",
    "masks": {
      "0": {
        "size": 21,
        "packed": "_mv8FlBugrt0ZdusrsElB_qv4AcAqlCVIxii-39jwSs4-gB6G_jG8E8huvKl0J2uqqsEYS_ts4A"
      },
      "1": {
        "size": 21,
        "packed": "_rv8ENButrt0xduhrsFNB_qv4A0AowEvibI3rivJa45trwBQs_uTsEWLuif10jcuv_8Ey4_o5oA"
      },
      "2": {
        "size": 21,
        "packed": "_gv8EpBuurt1VduqrsFpB_qv4BQAvjPjC_ssw5zp-ci2woB0I_lI0FyvupEt1H4uskkEWc_riwA"
      },
      "3": {
        "size": 21,
        "packed": "_ov8FFBugLt1VdunLsEdB_qv4B8At1pbC_sB9UdbIqi2woBZl_r-EFyvukpF1xOuskkE7x_tUAA"
      },
      "4": {
        "size": 21,
        "packed": "_sv8EJBulLt1JduursFJB_qv4BMAi_fIhcPPzaXxiA-qswBXr_urUEuzutY10kbunHEEKA_v-oA"
      },
      "5": {
        "size": 21,
        "packed": "_jv8FJBuurt1lduirsEJB_qv4BwAgrZyzOdsw5zJe85trwBUo_lI0EDeuhEt0nYun_8E28_riwA"
      },
      "6": {
        "size": 21,
        "packed": "_rv8FJBusrt0ldurrsERB_qv4AwAn5S6zOdl5w7RGk5trwBXr_vakFDeuoNl1_Aun_8E1__pwgA"
      },
      "7": {
        "size": 21,
        "packed": "_mv8E1Buhrt0ZdumrsFtB_qv4AMAlsUFIxiwslsq5bs4-gBoU_iP0F8hulY11A_uiqsEKA_slwA"
      }
    },
    "auto": {
      "size": 21,
      "packed": "_sv8EJBulLt1JduursFJB_qv4BMAi_fIhcPPzaXxiA-qswBXr_urUEuzutY10kbunHEEKA_v-oA"
    }
  },
  {
    "payload": "otpauth://totp/I:a@b.c?secret=AAAA&issuer=I",
    "masks": {
      "0": {
        "size": 33,
        "packed": "_jmxP8F6qpBuiAQLt0WopduqwALsErAhB_qqqv4ATdkAqjF_CW5sUFizvRMa5ScwEw1pAB9JSiiLJz4pEF9Jeu7pLvbJoWCadnKNtiq67JnO8Aai6q8Kpq_dDlrH6Ub7kd9hi8df-ABJTUa_ipFr8EZCEQusQA_N0HqGfuogHHsEVumC_v7MnYA"
      },
      "1": {
        "size": 33,
        "packed": "_uzkP8EQABBuvVFLt08CBdunlVLsFBqJB_qqqv4A53MAo2QqEsTG-vIm6EZPr42auag8VUob4IIhjmt8RQvj0ERDe6Oc9Eow3NgY43_vpjNkWqP3v_pYDAV3pw-SvBJRO3XL3pIK_QBj58Q_v8QqsEzosauhFV-d0tAs1ut1SS8E_EMo_quZyIA"
      },
      "2": {
        "size": 33,
        "packed": "_lo_P8E0klBusOeLt1Ymldus-OLsFlOtB_qqqv4BdToAvlLxPgziaLs9hfCU3YS-K-7nOPzHYssFH92nKLzDQg1nFhVHmYIUTpEDjsk01DpAyOUs0kyEjkxTNrlJ0aVxqTzvsyTR-IBHdcU_knLr0FXMMeuqeO_F1JkIRuuuJJkEbgoM_p1CpQA"
      },
      "3": {
        "size": 33,
        "packed": "_to_P8FZJJBui4ort1YmlduhTjrsET4ZB_qqqv4Bw-EAtz9HpYziaLsQsyv5ZqkI8I7nOPzCxBBoqLgR89DDQg1nos4qL26ilfyDjsk0wqEtfji6CSE0jkxTNGokZ37DclFZsyTR-IBqw0Z_qR9rEFXMMeunzj-t1_S-nuuuJJkE2NFh_vD0fgA"
      },
      "4": {
        "size": 33,
        "packed": "_p0jP8EXHFBunt9rt1E65duoiSLsFGtNB_qqqv4BBP0Ai5XtfLQB5oPei8h3TAOiWin7STvc7PPmke1EpoXbM8p7Z9Jb6Dr3wKnggPHXRb1cuSIwo4ufAHSwuImqX5xp2PvzwuPN-QBk-8X_vEoqUELQUSuuCS_d0qHryulNqqEEH80Q_tpe1IA"
      },
      "5": {
        "size": 33,
        "packed": "_mzkP8FUEFBusOeLt1pXVduk-OLsEFuNB_qqqv4B9zIAgtLxZxCTr6d9hfCU34yeqeg8VUof4MMln92nKLyyhREWFhVHmYo0zJkY43_vtjJgSuUs0kyFSVAi8rlJ0aVRKzTP3pIK_QBn98U_knLr0Em98fuieO_F0pEoxul1SS8E7AIs_p1CpQA"
      },
      "6": {
        "size": 33,
        "packed": "_uzkP8FXHFBuucMLt0pXVdut3HLsEd2VB_qqqv4A-wIAn_ZjS5CTr6d0oWLd_gqGyGg8VUoc7PPmkvk1YZiyhREWMocOvQwsrR8Y43_vugKjRtG-m2gVSVAi8isA9TdJSrLX3pIK_QBk-8X_u1ZrkFm98furXH-N1xcwpul1SS8E4DLv_rnQ7AA"
      },
      "7": {
        "size": 33,
        "packed": "_jmxP8Eo45BujJZLt0WopdugiSLsFiJpB_qqqv4ABP0AlqM2UG5sUFih9DeIobV5N51pAB9LAwwZb6xgNM1Jeu7pZ9Jb6HLTUuDNtiq65b1cuSTrzj1Cpq_dD35VoGKytU0oi8df-ABbBEY_jgMq0FZCEQumCS_d1OjPWuggHHsEH80Q_uyFuQA"
      }
    },
    "auto": {
      "size": 33,
      "packed": "_uzkP8FXHFBuucMLt0pXVdut3HLsEd2VB_qqqv4A-wIAn_ZjS5CTr6d0oWLd_gqGyGg8VUoc7PPmkvk1YZiyhREWMocOvQwsrR8Y43_vugKjRtG-m2gVSVAi8isA9TdJSrLX3pIK_QBk-8X_u1ZrkFm98furXH-N1xcwpul1SS8E4DLv_rnQ7AA"
    }
  },
  {
    "payload": "a longer otpauth payload to push the version up: otpauth://totp/Example:long.account@example.org?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
    "masks": {
      "0": {
        "size": 57,
        "packed": "_loL_2ujP8FQE3uAvJBui1GhNEzLt0ulHFgEJdutKRvn_9LsExTdF3UxB_qqqqqqqv4Avp3HmqsAqjNVP_uKCWYOxjiq6ATbvySIehIb5bTWIpKVgx-iGTtLGbHQJzIKxMkAjf9m99he5T4TqQqvuTlQ6hVOe7u5CkhshgSAAAhgw406QiYi6b--ypplzwS7tDH7lOHFqKS6oF6Ka78GJz6sEF6bL9c8N5Z6RvL8GtucKPaLUi4AAA3j_X9_oiI-dRt6zFdlUa2r6PK43sqMxeUREYBMfv9aLvjss-7AiuDeSbjAit1Cpc3-sBiENnOgYKtB2B-bo988ipzaVPd_EyA5k0W7u8toCz1ArMpmLO1n6HhiNfdK2eihGHnZfh1Pve7cdepI3yCCCFIyrhhWqbde-yHLTWdzHCmuRPfV36Icjf-TPIiuKpnPpTUBMa_yiKW7sRHSA3aUP_7q_YBFWhHggEb_jusau3Ur8EILjEo1ERuraR_7We-N0LYY6MlAauqdbqlet6sEV04RMZaC_tkePO-8E4A"
      },
      "1": {
        "size": 57,
        "packed": "_o9eqj73P8E6udEqFpBuvgT0YRnLt0EPtvKupdugfE_yqpLsFb53Hd-RB_qqqqqqqv4AFDdFMAEAo2YAfq7fEsykbJIAQq5O6nHdL0dOrx58iDg_Kbr3TG4eTOSCjZigbmOqJKozoo0LsGq5A6AFE5P6v0AbLu7sX2LGLK4qqqL1lthvF3N3oxUUYDDPZaHu4WSuwbSXAg4QCvQgwupTcmv5RQoxhX2WnTzQE6epT47Jfdwh-ISqqqd36Cov93d_PxHQZH3P8Qiuvaati5reR0-7GyrkV74Pe_255_pqIEp04xJq34gX8Jir5TIunNkKygHUjUrO9oppwDZw_l3VuYVsxhDu7p46oZfqBmDMhbgyvS03YKPgc0ILstNzK0ga6LuJIMDidYooovin-00D_OILsYth583Ztoz7EaKAivdOJ1U5liIEgpya8GBUZPvwIg8RG7t4AiPBfqu_-IBv8LFKKsR_u75K7iBqsEihJGCfsbumPEvuDL_d0hyyQmPqwuvIO_wL4v8E_eS7mzwo_oxLabrpRoA"
      },
      "2": {
        "size": 57,
        "packed": "_jmFx4gvP8EeK5gOhJBus7IvDK_Lt1grJLuKJdurEfvpxxLsF_dTH5axB_qqqqqqqv4Bhn5FokgAvlDbPxgEPgSA_tsk0OdVh8cGQvGV3RdYGnEbu_wsIdjFIVJeD9GE_CqOtRzozzvQ3d2Zkekhgdre0vbAQ1g3MqrivucOOOvu-260esWs0Rww8nnr9-c1jNJ1rAJLgEc0mL0EU1yIH90iKL0RFzSyD3X0fhFyIjgSEBQFas2OOO5v5Zz_msG-TRj09HTrcU6t0BK25iqCxQafGWPERj7UFvtii-1KsgNQcVtOsj7MnS5wiPoKDpAuWEjP4PwVmzyysj9UbBTxK8O3q6Y1gyjmI97OlCnoFA7p0JvsDRTA4QsvIJpXRv7BhQ1STQjG58MMMLG8lvvYkVTQw4JFdYT9JMogfBRb50GSpRwdBGsgEppBndaPCU3wsEY1ifJcA5UaPx1k_QBLYvFuuMV_lgiag5ar0FGFtGm7MfutUf_1YQ-F1FWW0CrOUusTVkrQj0kEb62fCXUM_rqQBAwyKwA"
      },
      "3": {
        "size": 57,
        "packed": "_rmFx4gvP8FznUNjMpBuiN-Z18LLt1grJLuKJdumpyPkcdLsEJrlFPsRB_qqqqqqqv4BMKVEFJMAtz1t_nWypYSA_tsk0Od4sRxr9Cr4ZjruwRytYJwsIdjFIVJbqQrpSvHjAnleFFZmBrGZkekhgdreZi2t9YNahEZUZYq444Zu-260esWsx4ddRKKGQTqjV7_Dd2_7gEc0mL0EUY_lqQZPnmajzFkE1BhCfhFyIjgSEE5o3BbjjjUb_vFPwaw-jRj09HTrcUWoZsq7UPrsRmspEg50Xj7UFvtii-wjBNg9x4Aja1N6RkPGU_oKDpAuWEji1id4LeffCRLit3lH8KO3q6Y1gyjjhQWjIvKFo2tfC_Za1njA4QsvIJpX8iWsM9Y_--RwPK6669w8lvvYkVTQ1Rkow1-Qkhe2p3ntPCwipRwdBGsgEpksKw3iv5fyayuDUp_qA5UaPx1k_QBm1DEDDkY_rWUq2PsrEFGFtGm7Mfug5yf419_t1zggC0d4iusTVkrQj0kE2Xbyv65h_tcm32GE8AA"
      },
      "4": {
        "size": 57,
        "packed": "_v6Ztk8zP8E9paDtCpBunYrMgpfLt183VXyWJduvYD_1ttLsFc-xEa5RB_qqqqqqqv4B97lF048Ai5fHft8YfLxjcOPHXt-2if_lzMl2TJBEa7YHyjswUB_ZUJVFgelnchJtOywLQQMzU-SB4C498B3CozHcMp8rQxIBMN_tttMN9VZX9P1PQJssg773hiAp_RVp3cVQDn_XFoXn3WxrkeXBpoQJZvOufrLoD9ZuU_8OYazm5PVtttaP66QflPl_3R_ohHP3EYmpodaql-qZRz59F1skSD43mPuBB_RSw8RMAJxSw_nQ7Ols-ULpgKjN1nAs7sT2FQRRI7hIHdPtWgSr2mEp8u_9reYtGhELmj4KXqMPgy3YkMwzUV1LNznd9MpOPLAlafvvvolfmMM7H2wzUgVZBEPhVQ08DdNHloaJKyT-ilPDnpqiE-5sh3XwwYEp-DVAAlIGftp4_IBo7NGNNsW_uDB6ja5qUEaZxG6nUTupIDvpEM-d0m11XhIt3unw2HIzAXEEHmqDeLIQ_v2MdcsuWoA"
      },
      "5": {
        "size": 57,
        "packed": "_g9eqj73P8F-qZAuBpBus7IvDK_Lt1Ra46f7pdujEfvpxxLsEf9zHZ6RB_qqqqqqqv4BBHZFIEAAgtDbPxgEZxjxOcdVF_sVh8cGQvGV3x94mHk7Ofr3TG4eTOSGjdmkfiKuNRzozzvQ3d3oVvVQRsav0vbAQ1g3MqLCPO8uuuP1lthvF3N3sxQQcHHLdec1jNJ1rAJKR1tFX6F1l1yIH90iKL0xlTySjX3UE6epT47JfZwl6MWuuuZv5Zz_msG-SxSFNGiasV6t0BK25iqCRw6_G2vkR74Pe_255_tqMAtw81Nusj7MnS5wiOZ7yYxfn1SP4PwVmzyysDd07hzRqcVsxhDu7p4-odbuFiHIlA7p0JvsDRSxJhde54YmRv7BhQ1STQDmZcsssrmn-00D_OILoYpl94zdpsogfBRb50GTYgBsw3dR1ppBndaPCU3wMk4VC_p8AiPBfqu_-IBr4PFOOsV_lgiag5ar0E30dHXK8eulUf_1YQ-F0l22UiLu0unIO_wL4v8E7aW_i30s_rqQBAwyKwA"
      },
      "6": {
        "size": 57,
        "packed": "_o9eqj73P8F9paDtCpBuupa9RYvLt0Ra46f7pduqNWvg45LsEHlrHBiRB_qqqqqqqv4ACEbGLHAAn_RJfjyWS5jxOcdVF_sco1VPZmPc_plg-f8jWHr3TG4eTOSFgelnchJtODh6hh9ClPnoVvVQRsav9mSJZ8p-FiTaXWk222X1lthvF3N3vyTTfEEIedOnxfbn5SbaR1tFX6F1l87BO09rDC8p9LqK7PvME6epT47Jfazm5PVttta_7Lhv0-U-CxSFNGiasVys9IK_wrrKRoinGu38Z74Pe_255_upPDuz_2Ot-xpe1AriweZ7yYxfn1SGxG5cv677kbFsj5rJyEVsxhDu7p49reYtGhELmSp7mb9-RDCxJhde54YmYmyIoZ8baYb-BE000z-n-00D_OILrbqm-7weqv6yNTDJrmUDYgBsw3dR1pgIuUTGLd_wU8gNanxkAiPBfqu_-IBo7NGNNsW_vywKyrIrkF30dHXK8eusdW_8RZ_N19uuM6T2sunIO_wL4v8E4ZV8h03v_p4CTSigYgA"
      },
      "7": {
        "size": 57,
        "packed": "_loL_2ujP8ECWl8S9JBuj8PoEN7Lt0ulHFgEJdunYD_1ttLsF4aVE-dxB_qqqqqqqv4A97lF048AlqEcP2nDUGYOxjiq6ATJ9gAaMzaJoSafBgDcp4-iGTtLGbHSbhaYje2SxW0v00oXwawTqQqvuTlQozHcMp8rQ1olopbJJJogw406QiYi4Jssg773hibykKOysHONqKS6oF6KapuUbho-WXrSC0V1EwQzRvL8GtucKNIZGwqSSSlr-e0_hrB_VRt6zFdlUampodaql-qdxXdZFRIEWv9aLvjss-5Sw8RMAJxSrk8LgV-3lJiENnOgYKtTkTsJ6vuuzg6TcGU2N7A5k0W7u8tqQhnS5e70ZH8uzOorEWVK2eihGHnZNznd9MpOPPgB-7LLLMByrhhWqbde8gVZBEPhVQvnYGWc-zBUjf-TPIiuKp1d7BGTeIvzrDfylYObA3aUP_7q_YBXEzFyyUZ_inlan-dq0FILjEo1ERuhIDvpEM-d1CRRzFsJTuidbqlet6sEHmqDeLIQ_stXGH31NwA"
      }
    },
    "auto": {
      "size": 57,
      "packed": "_loL_2ujP8ECWl8S9JBuj8PoEN7Lt0ulHFgEJdunYD_1ttLsF4aVE-dxB_qqqqqqqv4A97lF048AlqEcP2nDUGYOxjiq6ATJ9gAaMzaJoSafBgDcp4-iGTtLGbHSbhaYje2SxW0v00oXwawTqQqvuTlQozHcMp8rQ1olopbJJJogw406QiYi4Jssg773hibykKOysHONqKS6oF6KapuUbho-WXrSC0V1EwQzRvL8GtucKNIZGwqSSSlr-e0_hrB_VRt6zFdlUampodaql-qdxXdZFRIEWv9aLvjss-5Sw8RMAJxSrk8LgV-3lJiENnOgYKtTkTsJ6vuuzg6TcGU2N7A5k0W7u8tqQhnS5e70ZH8uzOorEWVK2eihGHnZNznd9MpOPPgB-7LLLMByrhhWqbde8gVZBEPhVQvnYGWc-zBUjf-TPIiuKp1d7BGTeIvzrDfylYObA3aUP_7q_YBXEzFyyUZ_inlan-dq0FILjEo1ERuhIDvpEM-d1CRRzFsJTuidbqlet6sEHmqDeLIQ_stXGH31NwA"
    }
  }
]
