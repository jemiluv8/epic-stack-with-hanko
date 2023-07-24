import { useEffect } from "react";

const endpoint: string = "https://a8661315-1380-4d4e-b64f-cb34ec563cb3.hanko.io";


const code = `
  import { register } from 'https://esm.sh/@teamhanko/hanko-elements@0.5.5-beta';

  register('${endpoint}', { shadow: true });
`;

export default function Profile() {
	useEffect(() => {
		// register the component
		// see: https://github.com/teamhanko/hanko/blob/main/frontend/elements/README.md#script
		import("@teamhanko/hanko-elements").then(({ Hanko, register}: any) => {
			// setHanko(new module.default(hankoApi));
			register(endpoint, {  shadow: true, injectStyles: true, hidePasskeyButtonOnLogin: true })
				.catch((error: any) => {
					console.log("hanko register error", error)
				});
		})
	}, []);
  return (
    <div className="profile">
      <hanko-profile></hanko-profile>
      <script type="module">
        {code}
      </script>
    </div>
  );
}