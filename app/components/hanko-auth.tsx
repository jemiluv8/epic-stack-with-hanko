// import { register } from "@teamhanko/hanko-elements";
import { useCallback, useEffect, useState } from "react";
import { ClientOnly } from 'remix-utils'
// import { redirect, type DataFunctionArgs } from '@remix-run'

// import { safeRedirect } from "remix-utils";

const hankoApi = "https://a8661315-1380-4d4e-b64f-cb34ec563cb3.hanko.io"

export interface iProps {
    redirectTo: string;
}

export default function HankoAuth({ redirectTo }: iProps) {

  const [hanko, setHanko] = useState<any>(); /*@TODO: properly type */

  const loginOrSignUp = async (hanko: any) => {
    const formData = new FormData()
    formData.set('email', hanko.user.email)

    const response = await fetch('/hanko', {
      method: "POST",
      body: formData
    });

    console.log("response", response)
  }

  const redirectAfterLogin = useCallback(() => {
    if (redirectTo) {
      // safeRedirect(redirectTo)
      
      window.location.href = redirectTo
    } else {
      // safeRedirect("/me")
      window.location.href = "/settings/profile"
    }
  }, [redirectTo]);

  useEffect(() => hanko?.onAuthFlowCompleted(() => {
    redirectAfterLogin();
  }), [hanko, redirectAfterLogin]);
  
  useEffect(() => {
    // register the component
    // see: https://github.com/teamhanko/hanko/blob/main/frontend/elements/README.md#script
    import("@teamhanko/hanko-elements").then(({ Hanko, register}: any) => {
        // setHanko(new module.default(hankoApi));

        register(hankoApi, {  shadow: true, injectStyles: true, hidePasskeyButtonOnLogin: true })
          .then(() => {
            const newHanko = new Hanko(hankoApi);
            setHanko(newHanko as any)
            loginOrSignUp(newHanko)
          })
          .catch((error: any) => {
            // handle error
            console.log("hanko register error", error)
          });
    })
  }, []);

  return (
    <div className="mx-auto w-full max-w-md px-8 bg-background text-foreground">
      <ClientOnly>
        { () => <hanko-auth /> }
      </ClientOnly>
    </div>
  );
}