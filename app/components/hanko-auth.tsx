import { useCallback, useEffect, useState } from "react";
import { ClientOnly } from 'remix-utils'

const hankoApi = "https://a8661315-1380-4d4e-b64f-cb34ec563cb3.hanko.io"

export interface iProps {
    redirectTo: string;
}

export default function HankoAuth({ redirectTo }: iProps) {

  const [hanko, setHanko] = useState<any>(); /*@TODO: properly type */

  const processHanko = async (hanko: any) => {
    const emails = await hanko.email.list()
    if (emails.length > 0) {
      // TODO: decide whether to use primary address?
      const redirectTo = `/verify-hanko?email=${emails[0].address}`
      window.location.href = redirectTo
    }
}

  const redirectAfterLogin = useCallback(() => {
    // successfully logged in, redirect to a page in your application
    if (redirectTo) {
      window.location.href = redirectTo
    } else {
      window.location.href = "/settings/profile"
    }
  }, [redirectTo]);

  useEffect(() => hanko?.onAuthFlowCompleted(() => {
    processHanko(hanko)
  }), [hanko, redirectAfterLogin]);
  
  useEffect(() => {
    // register the component
    // see: https://github.com/teamhanko/hanko/blob/main/frontend/elements/README.md#script
    import("@teamhanko/hanko-elements").then(({ Hanko, register}: any) => {
        // setHanko(new module.default(hankoApi));

        register(hankoApi, {  shadow: true, injectStyles: true, hidePasskeyButtonOnLogin: true })
          .then((res: any) => {
            const newHanko = new Hanko(hankoApi);
            setHanko(newHanko)
            // processHanko(newHanko)
          })
          .catch((error: any) => {
            // handle error
            console.log("hanko register error", error)
          });
    })
  }, [redirectAfterLogin]);

  return (
    <div className="mx-auto w-full max-w-md px-8 bg-background text-foreground">
      <ClientOnly>
        { () => <hanko-auth /> }
      </ClientOnly>
    </div>
  );
}